use actix_web::{web, App, HttpResponse, HttpServer, Result};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    signer::keypair::Keypair,
    signer::Signer,
    bs58,
    pubkey::Pubkey,
    instruction::{AccountMeta, Instruction},
};
use spl_token::instruction as token_instruction;
use base64;

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct CreateTokenResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

async fn generate_keypair() -> Result<HttpResponse> {
    let keypair = Keypair::new();
    let response = ApiResponse {
        success: true,
        data: Some(KeypairResponse {
            pubkey: keypair.pubkey().to_string(),
            secret: bs58::encode(&keypair.to_bytes()).into_string(),
        }),
        error: None,
    };
    
    Ok(HttpResponse::Ok().json(response))
}

async fn create_token(req: web::Json<CreateTokenRequest>) -> Result<HttpResponse> {
    // Parse public keys from base58 strings
    let mint_authority = match bs58::decode(&req.mint_authority).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pubkey) => pubkey,
            Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint authority public key".to_string()),
            })),
        },
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Invalid mint authority base58 string".to_string()),
        })),
    };

    let mint = match bs58::decode(&req.mint).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pubkey) => pubkey,
            Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint public key".to_string()),
            })),
        },
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Invalid mint base58 string".to_string()),
        })),
    };

    // Create initialize mint instruction
    let init_mint_ix = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None, // Freeze authority
        req.decimals,
    ).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!("Failed to create token instruction: {}", e))
    })?;

    // Convert instruction to response format
    let response = ApiResponse {
        success: true,
        data: Some(CreateTokenResponse {
            program_id: init_mint_ix.program_id.to_string(),
            accounts: init_mint_ix.accounts.iter().map(|acc| AccountInfo {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            }).collect(),
            instruction_data: base64::encode(init_mint_ix.data),
        }),
        error: None,
    };

    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Server starting on http://127.0.0.1:8080");
    
    HttpServer::new(|| {
        App::new()
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
