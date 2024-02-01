use luban_schema::sea_orm::DatabaseConnection;
use std::fs::OpenOptions;
use std::path::Path;
use uuid::Uuid;

use chrono::{DateTime, Utc};
use rocket::serde::json::Json;
use rocket::{get, post, routes, State};

use ::entity::{prelude::*, *};
use luban_schema::*;
use migration::MigratorTrait;

mod common;
use common::ProgressQuery;

use luban_core::{Entry, Index, ParamsG, PartySignup};

pub fn main() {
    let result = run_manager();

    println!("Rocket: deorbit.");

    if let Some(err) = result.err() {
        println!("Error: {err}");
    }
}

#[rocket::main]
pub async fn run_manager() -> Result<(), rocket::Error> {
    //     let mut my_config = Config::development();
    //     my_config.set_port(18001);
    //rocket::custom(my_config).mount("/", routes![get, set]).manage(db_mtx).launch();

    let db_path = "luban.db";
    let dba = match sea_orm::Database::connect(&format!("sqlite://{}", db_path)).await {
        Ok(db) => db,
        Err(e) => {
            println!("Failed to connect to local database: {}", e);
            println!("Creating a new database file: {}", db_path);
            // Create the database directory if it doesn't exist
            if let Some(parent) = Path::new(db_path).parent() {
                std::fs::create_dir_all(parent).expect("Failed to create database directory");
            }

            // Manually create the SQLite database file if it doesn't exist
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(db_path)
                .expect("Failed to create database file");
            let db = sea_orm::Database::connect(&format!("sqlite://{}", db_path))
                .await
                .expect("Failed to connect to new created database file");
            migration::Migrator::refresh(&db)
                .await
                .expect("Failed to run migrations");
            db
        }
    };

    rocket::build()
        .mount(
            "/",
            routes![
                req_code,
                delete_code,
                get,
                set,
                signup_keygen,
                signup_sign,
                ask_progress,
            ],
        )
        .manage(dba)
        .launch()
        .await
        .map(|_| ())
}

fn split_key(key: Index) -> (u16, u16, u16, String) {
    (key.party_from, key.party_to, key.round, key.uuid)
}

/// request a code for certain action.
///
/// action可以是: keygen 和 sign 等
#[post("/reqcode/<action>")]
async fn req_code(conn: &State<DatabaseConnection>, action: &str) -> Json<Result<String, String>> {
    let newuuid = Uuid::new_v4().to_string();
    let party_signup = PartySignup {
        party_id: 0,
        uuid: newuuid.clone(),
    };

    let db = conn as &DatabaseConnection; // 获取数据库连接对象. 该对象由Rocket管理.
    let form = post::Model {
        action: action.to_owned(),
        uuid: newuuid.to_owned(),
        text: serde_json::to_string(&party_signup).unwrap(),
        timestamp: Utc::now().to_string(),
        ..Default::default()
    };
    BasicOps::create_post(db, form) // 把form对象插入数据库
        .await
        .expect("req code failed");

    Json(Ok(newuuid))
}

/// delete a code for certain action.
///
/// action可以是: keygen 和 sign 等
#[post("/deletecode/<action>/<code>")]
async fn delete_code(
    conn: &State<DatabaseConnection>,
    action: &str,
    code: &str,
) -> Json<Result<String, String>> {
    let db = conn as &DatabaseConnection;
    // delete the post with the code
    let _ = BasicOps::delete_post_by_uuid(db, action.to_owned(), code.to_owned())
        .await
        .expect("delete code failed");
    Json(Ok("deleted ".to_string() + action + " code: " + code))
}

#[post("/get", data = "<request>")]
async fn get(
    conn: &State<DatabaseConnection>,
    request: Json<Index>,
) -> Json<Result<Entry, String>> {
    let index: Index = request.0;
    let db = conn as &DatabaseConnection;
    let (partyfrom, partyto, round, uuid) = split_key(index.to_owned());
    let post = BasicOps::find_post_text_by_uuid(db, partyfrom, partyto, round, uuid)
        .await
        .expect("search failed");
    // println!("get: {:?}", post);
    match post {
        Some(p) => {
            let entry = Entry {
                key: index,
                value: p,
            };
            Json(Ok(entry))
        }
        None => Json(Err("Nothing get".to_owned())),
    }
}

#[get("/ask_progress/<code>/<total>")]
async fn ask_progress(
    conn: &State<DatabaseConnection>,
    code: &str,
    total: &str,
) -> Json<Result<ProgressQuery, String>> {
    let db = conn as &DatabaseConnection;
    let total = match total.parse::<usize>() {
        Ok(__) => __,
        Err(_e) => {
            return Json(Err(format!(
                "Cannot parse \"{}\" into unsigned int.",
                total
            )));
        }
    };
    let mut query = ProgressQuery {
        total: total,
        rounds: vec![-1_i64; total],
        values: vec![String::new(); total],
    };
    for cdd in 0..total {
        let res = BasicOps::find_max_round_by_uuid(db, cdd as u16, code.to_string())
            .await
            .expect("search failed");
        query.rounds[cdd] = res.0 as i64;
        query.values[cdd] = res.1;
    }
    Json(Ok(query))
}

#[post("/set", data = "<request>")]
async fn set(conn: &State<DatabaseConnection>, request: Json<Entry>) -> Json<Result<(), String>> {
    let entry: Entry = request.0;
    let db = conn as &DatabaseConnection;
    let (partyfrom, partyto, round, uuid) = split_key(entry.key);

    let form = post::Model {
        partyfrom,
        partyto,
        round,
        uuid,
        text: entry.value,
        timestamp: Utc::now().to_string(),
        ..Default::default()
    };
    BasicOps::create_post(db, form)
        .await
        .expect("could not insert post");
    Json(Ok(()))
}

/// all action signup here
async fn signup(
    conn: &State<DatabaseConnection>,
    request: Json<ParamsG>,
    action: &str,
) -> Json<Result<PartySignup, String>> {
    let parties = request.n_actual;
    let key = action.to_owned() + &request.uuid;
    let db = conn as &DatabaseConnection;
    let post = BasicOps::find_post_by_uuid(db, action.to_owned(), request.uuid.to_owned())
        .await
        .expect("search failed");
    // println!("get: {:?}", post);
    let mut value = match post {
        Some(p) => p,
        None => return Json(Err(key + " uuid not existed.")),
    };

    let party_signup = {
        let client_signup: PartySignup = serde_json::from_str(&value.text).unwrap();
        if client_signup.party_id < parties {
            PartySignup {
                party_id: client_signup.party_id + 1,
                uuid: client_signup.uuid,
            }
        } else {
            PartySignup {
                party_id: 1,
                uuid: Uuid::new_v4().to_string(),
            }
        }
    };
    value.text = serde_json::to_string(&party_signup).unwrap();
    BasicOps::update_post_by_id(db, value.id, value)
        .await
        .expect("could not update post");
    Json(Ok(party_signup))
}

#[post("/signupkeygen", data = "<request>")]
async fn signup_keygen(
    conn: &State<DatabaseConnection>,
    request: Json<ParamsG>,
) -> Json<Result<PartySignup, String>> {
    signup(conn, request, "keygen").await
}

#[post("/signupsign", data = "<request>")]
async fn signup_sign(
    conn: &State<DatabaseConnection>,
    request: Json<ParamsG>,
) -> Json<Result<PartySignup, String>> {
    signup(conn, request, "sign").await
}
