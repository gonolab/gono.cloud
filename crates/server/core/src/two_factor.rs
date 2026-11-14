//! Two-step verification of accounts (`two_factor` and `recovery_codes` tables).
//!
//! Remote access is available only on accounts that have it enrolled
//! (`docs/connect-protocol.md`, section 13). Enrolment, the second step of the web sign-in and
//! recovery codes are part 2c of the remote connectivity plan; this module answers whether an
//! account has it.

use crate::{db::Pool, error::Result};

/// Whether account `user_id` has two-step verification enrolled.
pub async fn is_enrolled(pool: &Pool, user_id: i64) -> Result<bool> {
    let enrolled: Option<i64> = sqlx::query_scalar("SELECT 1 FROM two_factor WHERE user_id = ?1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    Ok(enrolled.is_some())
}
