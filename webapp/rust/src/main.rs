use axum::extract::{Path, Query};
use axum::Form;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use derive_more::Constructor;
use handlebars::{handlebars_helper, to_json, Handlebars};
use memcache::{Client, FromMemcacheValue, FromMemcacheValueExt, MemcacheError, ToMemcacheValue};
use once_cell::sync::Lazy;
use rand::{
    prelude::{SliceRandom, StdRng},
    thread_rng, SeedableRng,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::mysql::MySqlRow;
use sqlx::{pool, MySql, Row};
use std::{collections::HashMap, env, fmt::Write, process::Stdio};
use uuid::Uuid;

const POSTS_PER_PAGE: usize = 20;

static AGGREGATION_LOWER_CASE_NUM: Lazy<Vec<char>> = Lazy::new(|| {
    let mut az09 = Vec::new();
    for az in 'a' as u32..('z' as u32 + 1) {
        az09.push(char::from_u32(az).unwrap());
    }
    for s09 in '0' as u32..('9' as u32 + 1) {
        az09.push(char::from_u32(s09).unwrap());
    }
    az09
});

static ACCOUNT_NAME_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\A[0-9a-zA-Z_]{3,}\z").unwrap());
static PASSWORD_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\A[0-9a-zA-Z_]{6,}\z").unwrap());

#[derive(Debug, Serialize, Deserialize, Constructor, sqlx::FromRow)]

struct Count(i64);

#[derive(Debug, Serialize, Deserialize, Constructor, sqlx::FromRow, Clone)]
struct User {
    id: u64,
    account_name: String,
    passhash: String,
    authority: u64,
    del_flg: u64,
    created_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize, Constructor)]
struct StoreUser {
    user_id: Option<u64>,
    csrf_token: Option<String>,
    notice: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Constructor, sqlx::FromRow)]
struct Post {
    id: u64,
    user_id: u64,
    imgdata: Option<Vec<u8>>,
    body: String,
    mime: String,
    created_at: chrono::DateTime<Utc>,
}
#[derive(Debug, Serialize, Deserialize, Constructor)]
struct GrantedInfoPost {
    post: Post,
    comment_count: i64,
    comments: Vec<GrantedUserComment>,
    user: User,
    csrf_token: String,
}
#[derive(Debug, Serialize, Deserialize, Constructor, sqlx::FromRow)]
struct Comment {
    id: i32,
    post_id: i32,
    user_id: i32,
    comment: String,
    created_at: chrono::DateTime<Utc>,
}
#[derive(Debug, Serialize, Deserialize, Constructor)]
struct GrantedUserComment {
    comment: Comment,
    user: User,
}
#[derive(Debug, Serialize, Deserialize, Constructor)]
struct LoginRegisterParams {
    account_name: String,
    password: String,
}
#[derive(Debug, Serialize, Deserialize, Constructor)]
struct IndexParams {
    file: Vec<u8>,
    body: String,
    csrf_token: String,
}
#[derive(Debug, Serialize, Deserialize, Constructor)]
struct CommentParams {
    comment: String,
    post_id: u64,
    csrf_token: String,
}
#[derive(Debug, Default, Serialize, Deserialize, Constructor)]
struct BannedParams {
    uid: Vec<u64>,
    csrf_token: String,
}
#[derive(Debug, Serialize, Deserialize, Constructor)]
struct PostsQuery {
    max_created_at: String,
}
impl<W: std::io::Write> ToMemcacheValue<W> for StoreUser {
    fn get_flags(&self) -> u32 {
        0
    }
    fn get_length(&self) -> usize {
        bincode::serialize(self).unwrap().len()
    }
    fn write_to(&self, stream: &mut W) -> std::io::Result<()> {
        // めっちゃ雑なエラーハンドリング
        bincode::serialize_into(stream, self).unwrap();
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Constructor)]
struct GetPosts {
    max_created_at: String,
}

type MemcacheValue<T> = Result<T, MemcacheError>;

impl FromMemcacheValue for StoreUser {
    fn from_memcache_value(value: Vec<u8>, _: u32) -> MemcacheValue<Self> {
        Ok(bincode::deserialize::<StoreUser>(&value).unwrap())
    }
}

async fn db_initialize(pool: &sqlx::MySqlPool) {
    let sqls = vec![
        "DELETE FROM users WHERE id > 1000",
        "DELETE FROM posts WHERE id > 10000",
        "DELETE FROM comments WHERE id > 100000",
        "UPDATE users SET del_flg = 0",
        "UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
    ];
    for query in sqls {
        sqlx::query(query).execute(pool).await.unwrap();
    }
}

// 今回はsanitizeを行わないっぽい
async fn try_login(account_name: String, password: String, pool: &sqlx::MySqlPool) -> Option<User> {
    let u: User = sqlx::query_as("SELECT * FROM users WHERE account_name = ? AND del_flg = 0")
        .bind(account_name)
        .fetch_one(pool)
        .await
        .unwrap();
    if calculate_passhash(&u.account_name, password) == u.passhash {
        return Some(u);
    }
    None
}

fn validate_user(account_name: &str, password: String) -> bool {
    Regex::is_match(&ACCOUNT_NAME_REGEX, account_name)
        && Regex::is_match(&PASSWORD_REGEX, &password)
}

fn escapeshellarg(arg: &str) -> String {
    "'".to_string() + &arg.replace('\'', "'\\''") + "'"
}

fn digest(src: String) -> String {
    let process = std::process::Command::new("/bin/bash")
        .arg("-c")
        .arg("`printf \"%s\" `")
        .arg(escapeshellarg(&src))
        .stdout(Stdio::piped())
        .spawn();
    let process2 = std::process::Command::new("openssl")
        .arg("dgst")
        .arg("-sha512")
        .stdout(Stdio::piped())
        .spawn();
    let output = std::process::Command::new("sed")
        .arg("'s/^.*= //'")
        .output()
        .unwrap()
        .stdout
        .iter()
        .map(|&c| c as char)
        .collect::<String>();
    output.trim_end_matches('\n').to_string()
}

fn calculate_salt(account_name: String) -> String {
    digest(account_name)
}

fn calculate_passhash(account_name: &str, password: String) -> String {
    digest(password + ":" + &calculate_salt(account_name.to_string()))
}

fn get_session_key(
    req: &mut axum::http::Request<axum::body::Body>,
    client: &Client,
) -> Option<String> {
    let session_name = "isuconp-go.session=";
    req.headers()
        .get("Cookie")
        .and_then(|cookie| cookie.to_str().ok())
        .and_then(|cookie| {
            let cookie = cookie.split(';').collect::<Vec<_>>();
            let cookie = cookie
                .iter()
                .find(|&&cookie| cookie.starts_with(session_name))?;
            let cookie = cookie.trim_start_matches(session_name);
            Some(cookie.to_string())
        })
}

fn get_session(
    req: &mut axum::http::Request<axum::body::Body>,
    client: &Client,
) -> Option<StoreUser> {
    let key = get_session_key(req, client);
    if let Some(key) = key {
        client.get(&key).unwrap()
    } else {
        None
    }
}

fn set_session(
    res: &mut axum::http::Response<axum::body::Body>,
    client: &Client,
    store_user: StoreUser,
) {
    let key = Uuid::new_v4().to_string();
    client.set(&key, store_user, 60 * 30).unwrap();
    let cookie = format!("isuconp-go.session={}; Path=/", key);
    res.headers_mut()
        .insert("Set-Cookie", cookie.parse().unwrap());
}

async fn get_session_user(
    req: &mut axum::http::Request<axum::body::Body>,
    session: &Client,
    pool: &sqlx::MySqlPool,
) -> Option<User> {
    let store_user = get_session(req, session)?;
    let user_id = store_user.user_id?;
    let user = sqlx::query_as("SELECT * FROM `users` WHERE id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap();
    Some(user)
}

fn get_flash(
    res: &mut axum::http::Response<axum::body::Body>,
    req: &mut axum::http::Request<axum::body::Body>,
    key: String,
    client: &Client,
) -> String {
    let session = get_session(req, client).unwrap();
    // noticeのみ使用するっぽいのでnoticeのみ対応
    let value = if key == "notice" {
        session.notice
    } else {
        unreachable!("invalid flash key")
    };
    if let Some(value) = value {
        let session = Some(StoreUser {
            notice: None,
            user_id: session.user_id,
            csrf_token: session.csrf_token,
        });
        let key = get_session_key(req, client).unwrap();
        client.delete(&key);
        client.set(&key, session.unwrap(), 60 * 30).unwrap();
        value
    } else {
        "".to_string()
    }
}

fn set_flash(
    res: &mut axum::http::Response<axum::body::Body>,
    req: &mut axum::http::Request<axum::body::Body>,
    key: String,
    value: String,
    client: &Client,
) {
    let session = get_session(req, client).unwrap();
    let session = Some(StoreUser {
        notice: Some(value),
        user_id: session.user_id,
        csrf_token: session.csrf_token,
    });
    let key = get_session_key(req, client).unwrap();
    client.delete(&key);
    client.set(&key, session.unwrap(), 60 * 30).unwrap();
}

async fn make_posts(
    results: Vec<Post>,
    csrf_token: String,
    all_comments: bool,
    pool: &sqlx::MySqlPool,
) -> Option<Vec<GrantedInfoPost>> {
    let mut granted_info_posts = Vec::new();
    for p in results {
        let comment_count = sqlx::query_as::<MySql, Count>(
            "SELECT COUNT(*) AS `count` FROM `comments` WHERE `post_id` = ?",
        )
        .bind(p.id)
        .fetch_one(pool)
        .await
        .unwrap();
        let comments: Vec<Comment> = if all_comments {
            sqlx::query_as::<MySql, Comment>(
                "SELECT * FROM `comments` WHERE `post_id` = ? ORDER BY `created_at` DESC",
            )
            .bind(p.id)
            .fetch_all(pool)
            .await
            .unwrap()
        } else {
            sqlx::query_as::<MySql, Comment>(
                "SELECT * FROM `comments` WHERE `post_id` = ? ORDER BY `created_at` DESC LIMIT 3",
            )
            .bind(p.id)
            .fetch_all(pool)
            .await
            .unwrap()
        };
        let mut granted_comments = Vec::new();
        for comment in comments {
            let user = sqlx::query_as::<MySql, User>("SELECT * FROM `users` WHERE `id` = ?")
                .bind(comment.user_id)
                .fetch_optional(pool)
                .await
                .unwrap()
                .unwrap();
            println!("comment user {:?}", &user);
            granted_comments.push(GrantedUserComment::new(comment, user));
        }
        granted_comments.reverse();
        let user = sqlx::query_as::<MySql, User>("SELECT * FROM `users` WHERE `id` = ?")
            .bind(p.user_id)
            .fetch_optional(pool)
            .await
            .unwrap()
            .unwrap();
        println!("user {:?}", &user);
        if user.del_flg == 0 {
            granted_info_posts.push(GrantedInfoPost::new(
                p,
                comment_count.0,
                granted_comments,
                user,
                csrf_token.clone(),
            ))
        }
        if granted_info_posts.len() >= POSTS_PER_PAGE {
            break;
        }
    }
    Some(granted_info_posts)
}

handlebars_helper!(image_url: |p: GrantedInfoPost| {
    let ext = match p.post.mime.as_str() {
            "image/jpeg" => ".jpg",
            "image/png" => ".png",
            "image/gif" => ".gif",
            _ => "",
        };
    format!("/image/{}{}", p.post.id, ext)
});
handlebars_helper!(date_time_format: |create_at: DateTime<Utc>| {
    create_at.format("%Y-%m-%dT%H:%M:%S-07:00").to_string()
});

fn is_login(user: &User) -> bool {
    user.id != 0
}

fn get_csrf_token(req: &mut axum::http::Request<axum::body::Body>, client: &Client) -> String {
    let session = get_session(req, client);
    if let Some(session) = session {
        session.csrf_token.unwrap()
    } else {
        "".to_string()
    }
}

fn secure_random_str(b: u32) -> String {
    let mut rng = StdRng::from_rng(thread_rng()).unwrap();
    let mut rnd_str = Vec::new();
    for _ in 0..b {
        rnd_str.push(AGGREGATION_LOWER_CASE_NUM.choose(&mut rng).unwrap());
    }
    let rnd_str = rnd_str.iter().copied().collect();
    rnd_str
}

fn get_templ_path(filename: &str) -> String {
    format!("templates/{}", filename)
}

async fn get_initialize(
    req: &mut axum::http::Request<axum::body::Body>,
    res: &mut axum::http::Response<axum::body::Body>,
    client: Client,
    pool: &sqlx::MySqlPool,
) -> impl IntoResponse {
    db_initialize(pool).await;
    (StatusCode::OK, "initialized")
}

async fn get_login(
    req: &mut axum::http::Request<axum::body::Body>,
    res: &mut axum::http::Response<axum::body::Body>,
    client: &Client,
    pool: &sqlx::MySqlPool,
    handlebars: Handlebars<'_>,
) -> impl IntoResponse {
    let me = get_session_user(req, client, pool).await.unwrap();
    if is_login(&me) {
        return Redirect::to("/").into_response();
    }
    let body = {
        let mut map = HashMap::new();
        map.insert("me".to_string(), to_json(me));
        map.insert(
            "flash".to_string(),
            to_json(get_flash(res, req, "notice".to_string(), client)),
        );
        map.insert("parent".to_string(), to_json("layout"));
        println!("map {:?}", &map);

        handlebars.render(&get_templ_path("login"), &map).unwrap()
    };
    (StatusCode::OK, body).into_response()
}

async fn post_login(
    req: &mut axum::http::Request<axum::body::Body>,
    res: &mut axum::http::Response<axum::body::Body>,
    client: &Client,
    pool: &sqlx::MySqlPool,
    form: Form<LoginRegisterParams>,
) -> impl IntoResponse {
    let me = get_session_user(req, client, pool).await.unwrap();
    if is_login(&me) {
        return Redirect::to("/").into_response();
    }
    let account_name = &form.account_name;
    let password = &form.password;
    let user = try_login(account_name.to_string(), password.to_string(), pool).await;
    if let Some(user) = user {
        let store_user = StoreUser::new(
            Some(user.id),
            Some(secure_random_str(32)),
            Some(user.account_name),
        );
        set_session(res, client, store_user);
        return (StatusCode::FOUND, Redirect::to("/")).into_response();
    }
    set_flash(
        res,
        req,
        "notice".to_string(),
        "ログインに失敗しました".to_string(),
        client,
    );
    (StatusCode::NOT_FOUND, Redirect::to("/login")).into_response()
}

async fn get_register(
    req: &mut axum::http::Request<axum::body::Body>,
    res: &mut axum::http::Response<axum::body::Body>,
    client: &Client,
    pool: &sqlx::MySqlPool,
    handlebars: Handlebars<'_>,
) -> impl IntoResponse {
    let me = get_session_user(req, client, pool).await.unwrap();
    if is_login(&me) {
        return (StatusCode::FOUND, Redirect::to("/")).into_response();
    }
    let body = {
        let mut map = HashMap::new();
        map.insert("me".to_string(), to_json(me));
        map.insert(
            "flash".to_string(),
            to_json(get_flash(res, req, "notice".to_string(), client)),
        );
        map.insert("parent".to_string(), to_json("layout"));
        println!("map {:?}", &map);

        handlebars
            .render(&get_templ_path("register"), &map)
            .unwrap()
    };
    (StatusCode::OK, body).into_response()
}

async fn post_register(
    req: &mut axum::http::Request<axum::body::Body>,
    res: &mut axum::http::Response<axum::body::Body>,
    client: &Client,
    pool: &sqlx::MySqlPool,
    form: Form<LoginRegisterParams>,
) -> impl IntoResponse {
    let me = get_session_user(req, client, pool).await.unwrap();
    if is_login(&me) {
        return (StatusCode::FOUND, Redirect::to("/")).into_response();
    }
    let account_name = &form.account_name;
    let password = &form.password;
    let validated = validate_user(account_name, password.to_string());
    if !validated {
        set_flash(
            res,
            req,
            "notice".to_string(),
            "アカウント名は3文字以上、パスワードは6文字以上である必要があります".to_string(),
            client,
        );
        return (StatusCode::NOT_FOUND, Redirect::to("/register")).into_response();
    }
    // check user `me` exists at db
    let exists = sqlx::query("SELECT 1 FROM users WHERE `account_name` = ?")
        .bind(account_name)
        .fetch_optional(pool)
        .await
        .unwrap();
    if exists.is_some() {
        set_flash(
            res,
            req,
            "notice".to_string(),
            "アカウント名がすでに使われています".to_string(),
            client,
        );
        return (StatusCode::FOUND, Redirect::to("/register")).into_response();
    }
    let uid = sqlx::query("INSERT INTO `users` (`account_name`, `passhash`) VALUES (?, ?)")
        .bind(account_name)
        .bind(calculate_passhash(account_name, password.to_string()))
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
    let store_user = StoreUser::new(Some(uid), Some(secure_random_str(32)), None);
    set_session(res, client, store_user);
    (StatusCode::FOUND, Redirect::to("/")).into_response()
}

fn get_logout(
    req: &mut axum::http::Request<axum::body::Body>,
    res: &mut axum::http::Response<axum::body::Body>,
    client: &Client,
) -> impl IntoResponse {
    let key = get_session_key(req, client).unwrap();
    let store_user = get_session(req, client);
    if let Some(store_user) = store_user {
        // uidを消して保存し直す
        // TODO: cookieのMaxAgeを-1にする ref. https://github.com/catatsuy/private-isu/blob/587a4d1035a9da2a1f154ceba5d8c04a89b9b4ea/webapp/golang/app.go#L375-L382
        let new_store_user = StoreUser::new(None, store_user.csrf_token, store_user.notice);
        client.delete(&key);
        client.set(&key, new_store_user, 60 * 30);
    }
    (StatusCode::FOUND, Redirect::to("/")).into_response()
}

async fn get_index(
    req: &mut axum::http::Request<axum::body::Body>,
    res: &mut axum::http::Response<axum::body::Body>,
    client: &Client,
    pool: &sqlx::MySqlPool,
    handlebars: Handlebars<'_>,
) -> impl IntoResponse {
    let me = get_session_user(req, client, pool).await.unwrap();
    let results = sqlx::query_as::<MySql, Post>("SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` ORDER BY `created_at` DESC")
        .fetch_all(pool)
        .await
        .unwrap();
    let csrf_token = get_csrf_token(req, client);
    let posts: Vec<GrantedInfoPost> = make_posts(results, csrf_token, false, pool).await.unwrap();

    let body = {
        let mut map = HashMap::new();
        map.insert("posts".to_string(), to_json(posts));
        map.insert("me".to_string(), to_json(me));
        map.insert(
            "csrf_token".to_string(),
            to_json(get_csrf_token(req, client)),
        );
        map.insert(
            "flash".to_string(),
            to_json(get_flash(res, req, "notice".to_string(), client)),
        );
        map.insert("post_parent".to_string(), to_json("posts"));
        map.insert("posts_parent".to_string(), to_json("index"));
        map.insert("content_parent".to_string(), to_json("layout"));
        println!("map {:?}", &map);

        handlebars.render(&get_templ_path("post"), &map).unwrap()
    };
    (StatusCode::OK, body).into_response()
}

async fn get_account_name(
    req: &mut axum::http::Request<axum::body::Body>,
    res: &mut axum::http::Response<axum::body::Body>,
    client: &Client,
    pool: &sqlx::MySqlPool,
    handlebars: Handlebars<'_>,
    Path(account_name): Path<String>,
) -> impl IntoResponse {
    let me = get_session_user(req, client, pool).await.unwrap();
    let user = sqlx::query_as::<MySql, User>(
        "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0",
    )
    .bind(account_name)
    .fetch_optional(pool)
    .await
    .unwrap();
    if user.is_none() {
        return (StatusCode::NOT_FOUND, "404 Not Found").into_response();
    }
    let user = user.unwrap();
    let results = sqlx::query_as::<MySql, Post>("SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC")
        .bind(user.id)
        .fetch_all(pool)
        .await
        .unwrap();
    let csrf_token = get_csrf_token(req, client);
    let posts: Vec<GrantedInfoPost> = make_posts(results, csrf_token, false, pool).await.unwrap();

    let comment_count =
        sqlx::query("SELECT COUNT(*) AS `count` FROM `comments` WHERE `user_id` = ?")
            .bind(user.id)
            .fetch_one(pool)
            .await
            .unwrap()
            .get::<u64, _>("count");
    let post_ids: Vec<u64> = sqlx::query("SELECT `id` FROM `posts` WHERE `user_id` = ?")
        .bind(user.id)
        .fetch_all(pool)
        .await
        .unwrap()
        .iter()
        .map(|row| row.get::<u64, _>("id"))
        .collect::<Vec<u64>>();
    let post_count = post_ids.len();

    let commented_count = if post_count > 0 {
        let mut s = Vec::new();
        for _pid in &post_ids {
            s.push("?".to_string());
        }
        let place_holder = s.join(",");
        #[derive(Debug, sqlx::FromRow)]
        struct CommentedCount {
            count: u64,
        }
        let q = format!(
            "SELECT COUNT(*) AS `count` FROM `comments` WHERE `post_id` IN ({})",
            place_holder
        );
        let mut query = sqlx::query_as::<MySql, CommentedCount>(&q);
        for pid in &post_ids {
            query = query.bind(pid);
        }
        let commented_count = query.fetch_one(pool).await.unwrap();
        commented_count.count
    } else {
        0
    };

    let body = {
        let mut map = HashMap::new();

        map.insert("posts".to_string(), to_json(posts));
        map.insert("user".to_string(), to_json(user));
        map.insert("post_count".to_string(), to_json(post_count));
        map.insert("comment_count".to_string(), to_json(comment_count));
        map.insert("commented_count".to_string(), to_json(commented_count));
        map.insert("me".to_string(), to_json(me));

        map.insert("post_parent".to_string(), to_json("posts"));
        map.insert("posts_parent".to_string(), to_json("user"));
        map.insert("content_parent".to_string(), to_json("layout"));
        println!("map {:?}", &map);

        handlebars.render(&get_templ_path("post"), &map).unwrap()
    };
    (StatusCode::OK, body).into_response()
}

async fn get_posts(
    req: &mut axum::http::Request<axum::body::Body>,
    res: &mut axum::http::Response<axum::body::Body>,
    client: &Client,
    pool: &sqlx::MySqlPool,
    handlebars: Handlebars<'_>,
    urlquery: Query<GetPosts>,
) -> impl IntoResponse {
    let max_created_at = &urlquery.max_created_at;
    // parse max_created_at with iso8601 bia chrono
    let max_created_at = chrono::DateTime::parse_from_rfc3339(max_created_at)
        .unwrap()
        .with_timezone(&chrono::Utc);
    let results = sqlx::query_as::<MySql, Post>(
        "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `created_at` <= ? ORDER BY `created_at` DESC",
    )
    .bind(max_created_at.to_rfc3339())
    .fetch_all(pool)
    .await
    .unwrap();
    let csrf_token = get_csrf_token(req, client);
    let posts: Vec<GrantedInfoPost> = make_posts(results, csrf_token, false, pool).await.unwrap();

    if posts.is_empty() {
        return (StatusCode::NOT_FOUND, "404 Not Found").into_response();
    }

    let body = {
        let mut map = HashMap::new();
        map.insert("posts".to_string(), to_json(posts));
        map.insert("post_parent".to_string(), to_json("posts_stand_alone"));
        println!("map {:?}", &map);

        handlebars.render(&get_templ_path("post"), &map).unwrap()
    };
    (StatusCode::OK, body).into_response()
}

async fn get_posts_id(
    req: &mut axum::http::Request<axum::body::Body>,
    res: &mut axum::http::Response<axum::body::Body>,
    client: &Client,
    pool: &sqlx::MySqlPool,
    handlebars: Handlebars<'_>,
    Path(pid): Path<u64>,
) -> impl IntoResponse {
    let results = sqlx::query_as::<MySql, Post>("SELECT * FROM `posts` WHERE `id` = ?")
        .bind(pid)
        .fetch_all(pool)
        .await
        .unwrap();
    let csrf_token = get_csrf_token(req, client);
    let posts: Vec<GrantedInfoPost> = make_posts(results, csrf_token, false, pool).await.unwrap();

    if posts.is_empty() {
        return (StatusCode::NOT_FOUND, "404 Not Found").into_response();
    }

    let p = &posts[0];

    let me = get_session_user(req, client, pool).await.unwrap();

    let body = {
        let mut post = serde_json::to_value(p).unwrap();
        let mut map = post.as_object_mut().unwrap();
        map.insert("me".to_string(), to_json(me));

        map.insert("post_parent".to_string(), to_json("post_id"));
        map.insert("content_parent".to_string(), to_json("layout"));

        println!("map {:?}", &map);

        handlebars.render(&get_templ_path("post"), &map).unwrap()
    };
    (StatusCode::OK, body).into_response()
}

// TODO
async fn post_index(
    req: &mut axum::http::Request<axum::body::Body>,
    res: &mut axum::http::Response<axum::body::Body>,
    client: &Client,
    pool: &sqlx::MySqlPool,
    handlebars: Handlebars<'_>,
    urlquery: Query<GetPosts>,
) -> impl IntoResponse {
    let max_created_at = &urlquery.max_created_at;

    let max_created_at = chrono::DateTime::parse_from_rfc3339(max_created_at)
        .unwrap()
        .with_timezone(&chrono::Utc);
    let results = sqlx::query_as::<MySql, Post>(
        "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `created_at` <= ? ORDER BY `created_at` DESC",
    )
    .bind(max_created_at.to_rfc3339())
    .fetch_all(pool)
    .await
    .unwrap();
    let csrf_token = get_csrf_token(req, client);
    let posts: Vec<GrantedInfoPost> = make_posts(results, csrf_token, false, pool).await.unwrap();

    if posts.is_empty() {
        return (StatusCode::NOT_FOUND, "404 Not Found").into_response();
    }

    let body = {
        let mut map = HashMap::new();
        map.insert("posts".to_string(), to_json(posts));
        map.insert("post_parent".to_string(), to_json("posts_stand_alone"));
        println!("map {:?}", &map);

        handlebars.render(&get_templ_path("post"), &map).unwrap()
    };
    (StatusCode::OK, body).into_response()
}

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    // get environment variable or use default
    let host = env::var("ISUCONP_DB_HOST").unwrap_or_else(|_| "localhost".to_string());
    let port = env::var("ISUCONP_DB_PORT")
        .ok()
        .and_then(|it| it.parse().ok())
        .unwrap_or(3306);
    let user = env::var("ISUCONP_DB_USER").unwrap_or_else(|_| "root".to_string());
    let password = env::var("ISUCONP_DB_PASSWORD").unwrap_or_else(|_| "".to_string());
    let dbname = env::var("ISUCONP_DB_NAME").unwrap_or_else(|_| "isuconp".to_string());
    let dsn = format!(
        "mysql://{}:{}@{}:{}/{}?charset=utf8mb4&parseTime=true&loc=Local",
        user, password, host, port, dbname
    );

    // connect to mysql
    println!("dsn: {}", dsn);
    let pool = sqlx::MySqlPool::connect(&dsn).await.unwrap();

    // build our application with a route
    let app = Router::new();
    // `GET /` goes to `root`
    // .route("/", get(root))
    // // `POST /users` goes to `create_user`
    // .route("/users", post(create_user));

    // run our app with hyper
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

// // basic handler that responds with a static string
// async fn root() -> &'static str {
//     "Hello, World! changed"
// }

// async fn create_user(
//     // this argument tells axum to parse the request body
//     // as JSON into a `CreateUser` type
//     Json(payload): Json<CreateUser>,
// ) -> impl IntoResponse {
//     // insert your application logic here
//     let user = User {
//         id: 1337,
//         username: payload.username,
//     };

//     // this will be converted into a JSON response
//     // with a status code of `201 Created`
//     (StatusCode::CREATED, Json(user))
// }

// // the input to our `create_user` handler
// #[derive(Deserialize)]
// struct CreateUser {
//     username: String,
// }

// // the output to our `create_user` handler
// #[derive(Serialize)]
// struct User {
//     id: u64,
//     username: String,
// }
