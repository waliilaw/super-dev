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
use std::env;
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

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Serialize)]
struct MintTokenResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
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

async fn mint_token(req: web::Json<MintTokenRequest>) -> Result<HttpResponse> {
    // Parse public keys from base58 strings
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

    let destination = match bs58::decode(&req.destination).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pubkey) => pubkey,
            Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid destination public key".to_string()),
            })),
        },
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Invalid destination base58 string".to_string()),
        })),
    };

    let authority = match bs58::decode(&req.authority).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pubkey) => pubkey,
            Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid authority public key".to_string()),
            })),
        },
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Invalid authority base58 string".to_string()),
        })),
    };

    // Create mint-to instruction
    let mint_to_ix = token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        req.amount,
    ).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!("Failed to create mint-to instruction: {}", e))
    })?;

    let response = ApiResponse {
        success: true,
        data: Some(MintTokenResponse {
            program_id: mint_to_ix.program_id.to_string(),
            accounts: mint_to_ix.accounts.iter().map(|acc| AccountInfo {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            }).collect(),
            instruction_data: base64::encode(mint_to_ix.data),
        }),
        error: None,
    };

    Ok(HttpResponse::Ok().json(response))
}

async fn sign_message(req: web::Json<SignMessageRequest>) -> Result<HttpResponse> {
    // Validate request fields
    if req.message.is_empty() || req.secret.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        }));
    }

    // Decode secret key from base58
    let secret_key_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Invalid secret key format".to_string()),
        })),
    };

    // Create keypair from secret key
    let keypair = match Keypair::from_bytes(&secret_key_bytes) {
        Ok(kp) => kp,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Invalid secret key".to_string()),
        })),
    };

    // Sign the message
    let message_bytes = req.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);

    let response = ApiResponse {
        success: true,
        data: Some(SignMessageResponse {
            signature: base64::encode(signature.as_ref()),
            public_key: bs58::encode(keypair.pubkey().as_ref()).into_string(),
            message: req.message.clone(),
        }),
        error: None,
    };

    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Get port from environment (Railway will provide this)
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let bind_address = format!("0.0.0.0:{}", port);
    
    println!("Starting server on {}", bind_address);
    
    HttpServer::new(|| {
        App::new()
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
            .route("/token/mint", web::post().to(mint_token))
            .route("/message/sign", web::post().to(sign_message))
    })
    .bind(bind_address)?
    .run()
    .await
}
