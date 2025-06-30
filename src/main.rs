use actix_cors::Cors;
use actix_web::{
    middleware::{Logger, NormalizePath},
    web, App, HttpResponse, Result, HttpServer,
};
use chrono::Utc;
use dotenv::dotenv;
use log::{info, error, warn};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    signer::keypair::Keypair,
    signer::Signer,
    bs58,
    pubkey::Pubkey,
    instruction::{AccountMeta, Instruction},
};
use spl_token::instruction as token_instruction;
use std::env;
use base64;

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    timestamp: String,
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

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    timestamp: String,
}

async fn health_check() -> Result<HttpResponse> {
    info!("Health check endpoint called");
    Ok(HttpResponse::Ok().json(HealthResponse {
        status: "healthy".to_string(),
        timestamp: Utc::now().to_rfc3339(),
    }))
}

async fn generate_keypair() -> Result<HttpResponse> {
    info!("Generating new Solana keypair");
    
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(&keypair.to_bytes()).into_string();
    
    info!("Generated keypair with public key: {}", pubkey);
    
    let response = ApiResponse {
        success: true,
        data: Some(KeypairResponse {
            pubkey,
            secret,
        }),
        error: None,
        timestamp: Utc::now().to_rfc3339(),
    };
    
    Ok(HttpResponse::Ok().json(response))
}

async fn create_token(req: web::Json<CreateTokenRequest>) -> Result<HttpResponse> {
    info!("Processing token creation request");
    info!("Mint authority: {}", req.mint_authority);
    info!("Mint address: {}", req.mint);
    info!("Decimals: {}", req.decimals);
    
    // Parse public keys from base58 strings
    let mint_authority = match bs58::decode(&req.mint_authority).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pubkey) => pubkey,
            Err(e) => {
                error!("Invalid mint authority public key: {}", e);
                return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some("Invalid mint authority public key".to_string()),
                    timestamp: Utc::now().to_rfc3339(),
                }));
            }
        },
        Err(e) => {
            error!("Invalid mint authority base58 string: {}", e);
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint authority base58 string".to_string()),
                timestamp: Utc::now().to_rfc3339(),
            }));
        }
    };

    let mint = match bs58::decode(&req.mint).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pubkey) => pubkey,
            Err(e) => {
                error!("Invalid mint public key: {}", e);
                return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some("Invalid mint public key".to_string()),
                    timestamp: Utc::now().to_rfc3339(),
                }));
            }
        },
        Err(e) => {
            error!("Invalid mint base58 string: {}", e);
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint base58 string".to_string()),
                timestamp: Utc::now().to_rfc3339(),
            }));
        }
    };

    // Create initialize mint instruction
    let init_mint_ix = match token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None, // Freeze authority
        req.decimals,
    ) {
        Ok(ix) => ix,
        Err(e) => {
            error!("Failed to create token instruction: {}", e);
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(format!("Failed to create token instruction: {}", e)),
                timestamp: Utc::now().to_rfc3339(),
            }));
        }
    };

    info!("Successfully created token initialization instruction");
    
    // Convert instruction to response format
    let response = ApiResponse {
        success: true,
        data: Some(CreateTokenResponse {
            program_id: init_mint_ix.program_id.to_string(),
            accounts: init_mint_ix.accounts.iter().map(|acc| {
                info!("Account in instruction: {}", acc.pubkey);
                AccountInfo {
                    pubkey: acc.pubkey.to_string(),
                    is_signer: acc.is_signer,
                    is_writable: acc.is_writable,
                }
            }).collect(),
            instruction_data: base64::encode(init_mint_ix.data),
        }),
        error: None,
        timestamp: Utc::now().to_rfc3339(),
    };

    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables
    dotenv().ok();
    
    // Initialize logger
    env_logger::init();
    
    // Get configuration from environment
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let allowed_origins = env::var("ALLOWED_ORIGINS").unwrap_or_else(|_| "*".to_string());
    
    let bind_address = format!("{}:{}", host, port);
    info!("Starting server on {}", bind_address);
    
    HttpServer::new(move || {
        // Configure CORS
        let cors = Cors::default()
            .allowed_origin(&allowed_origins)
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec!["Content-Type"])
            .max_age(3600);
            
        App::new()
            .wrap(cors)
            .wrap(Logger::default())
            .wrap(NormalizePath::trim())
            // Health check endpoint
            .route("/health", web::get().to(health_check))
            // API endpoints
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
    })
    .bind(&bind_address)?
    .run()
    .await
}
