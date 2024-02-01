use ::entity::{post, post::Entity as Post};
use sea_orm::*;

pub struct BasicOps;

impl BasicOps {
    pub async fn find_post_by_id(db: &DbConn, id: u16) -> Result<Option<post::Model>, DbErr> {
        Post::find_by_id(id).one(db).await
    }

    /// If ok, returns (post models, num pages).
    pub async fn find_posts_in_page(
        db: &DbConn,
        page: u64,
        posts_per_page: u64,
    ) -> Result<(Vec<post::Model>, u64), DbErr> {
        // Setup paginator
        let paginator = Post::find()
            .order_by_asc(post::Column::Id)
            .paginate(db, posts_per_page);
        let num_pages = paginator.num_pages().await?;

        // Fetch paginated posts
        paginator.fetch_page(page - 1).await.map(|p| (p, num_pages))
    }

    pub async fn create_post(
        db: &DbConn,
        form_data: post::Model,
    ) -> Result<post::ActiveModel, DbErr> {
        post::ActiveModel {
            partyfrom: Set(form_data.partyfrom.to_owned()),
            partyto: Set(form_data.partyto.to_owned()),
            round: Set(form_data.round.to_owned()),
            action: Set(form_data.action.to_owned()),
            uuid: Set(form_data.uuid.to_owned()),
            text: Set(form_data.text.to_owned()),
            timestamp: Set(form_data.timestamp.to_owned()),
            ..Default::default()
        }
        .save(db)
        .await
    }

    pub async fn update_post_by_id(
        db: &DbConn,
        id: i32,
        form_data: post::Model,
    ) -> Result<post::Model, DbErr> {
        let post: post::ActiveModel = Post::find_by_id(id)
            .one(db)
            .await?
            .ok_or(DbErr::Custom("Cannot find post.".to_owned()))
            .map(Into::into)?;

        post::ActiveModel {
            id: post.id,
            partyfrom: Set(form_data.partyfrom.to_owned()),
            partyto: Set(form_data.partyto.to_owned()),
            round: Set(form_data.round.to_owned()),
            action: Set(form_data.action.to_owned()),
            uuid: Set(form_data.uuid.to_owned()),
            text: Set(form_data.text.to_owned()),
            timestamp: Set(form_data.timestamp.to_owned()),
        }
        .update(db)
        .await
    }

    pub async fn delete_post(db: &DbConn, id: u16) -> Result<DeleteResult, DbErr> {
        let post: post::ActiveModel = Post::find_by_id(id)
            .one(db)
            .await?
            .ok_or(DbErr::Custom("Cannot find post.".to_owned()))
            .map(Into::into)?;

        post.delete(db).await
    }

    //search post by uuid and partyfrom, return the max round and text of those posts
    pub async fn find_max_round_by_uuid(
        db: &DbConn,
        partyfrom: u16,
        uuid: String,
    ) -> Result<(u16, String), DbErr> {
        Post::find()
            .filter(post::Column::Partyfrom.eq(partyfrom))
            .filter(post::Column::Uuid.eq(uuid))
            .all(db)
            .await?
            .into_iter()
            .map(|x| (x.round, x.text))
            .max()
            .ok_or(DbErr::Custom("Cannot find max round.".to_owned()))
    }

    //search post by uuid and action, return column text
    pub async fn find_post_text_by_uuid(
        db: &DbConn,
        partyfrom: u16,
        partyto: u16,
        round: u16,
        uuid: String,
    ) -> Result<Option<String>, DbErr> {
        Post::find()
            .filter(post::Column::Partyfrom.eq(partyfrom))
            .filter(post::Column::Partyto.eq(partyto))
            .filter(post::Column::Round.eq(round))
            .filter(post::Column::Uuid.eq(uuid))
            .one(db)
            .await
            .map(|x| x.map(|y| y.text))
    }

    // search post by uuid and action, return post model
    pub async fn find_post_by_uuid(
        db: &DbConn,
        action: String,
        uuid: String,
    ) -> Result<Option<post::Model>, DbErr> {
        Post::find()
            .filter(post::Column::Action.eq(action))
            .filter(post::Column::Uuid.eq(uuid))
            .one(db)
            .await
    }

    // delete post by uuid and action
    pub async fn delete_post_by_uuid(
        db: &DbConn,
        action: String,
        uuid: String,
    ) -> Result<DeleteResult, DbErr> {
        let post: post::ActiveModel = Post::find()
            .filter(post::Column::Uuid.eq(uuid))
            .filter(post::Column::Action.eq(action))
            .one(db)
            .await?
            .ok_or(DbErr::Custom("Cannot find code.".to_owned()))
            .map(Into::into)?;

        post.delete(db).await
    }

    pub async fn delete_all_posts(db: &DbConn) -> Result<DeleteResult, DbErr> {
        Post::delete_many().exec(db).await
    }
}
