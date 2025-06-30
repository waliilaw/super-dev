use actix_web::{web, App, HttpResponse, HttpServer, Result};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    signer::keypair::Keypair,
    signer::Signer,
    bs58,
    pubkey::Pubkey,
    instruction::{AccountMeta, Instruction},
    system_instruction,
    signature::Signature,
};
use spl_token::instruction as token_instruction;
use std::env;
use base64;

// Request shapes
#[derive(Deserialize)]
struct CreateTokenRequest {
    decimals: u8,
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    private_key: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    public_key: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    to: String,
    from: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

// Response shapes
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Serialize)]
struct KeypairResponse {
    public_key: String,
    private_key: String,
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
struct MintTokenResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    is_valid: bool,
}

#[derive(Serialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

// Generate keypair
async fn generate_keypair() -> Result<HttpResponse> {
    // Fresh keypair
    let keypair = Keypair::new();
    
    // Pack response
    let response = ApiResponse {
        success: true,
        data: Some(KeypairResponse {
            public_key: keypair.pubkey().to_string(),
            private_key: bs58.encode(keypair.secret()).into_string(),
        }),
        error: None,
    };

    Ok(HttpResponse::Ok().json(response))
}

// Create token
async fn create_token(req: web::Json<CreateTokenRequest>) -> Result<HttpResponse> {
    // Fresh authority
    let authority = Keypair::new();
    
    // Fresh mint
    let mint = Keypair::new();

    // Build instruction
    let create_ix = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint.pubkey(),
        &authority.pubkey(),
        None,
        req.decimals,
    ).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!("Failed to create token: {}", e))
    })?;

    // Pack response
    let response = ApiResponse {
        success: true,
        data: Some(CreateTokenResponse {
            program_id: create_ix.program_id.to_string(),
            accounts: create_ix.accounts.iter().map(|acc| AccountInfo {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            }).collect(),
            instruction_data: base64::encode(&create_ix.data),
        }),
        error: None,
    };

    Ok(HttpResponse::Ok().json(response))
}

// Mint tokens
async fn mint_token(req: web::Json<MintTokenRequest>) -> Result<HttpResponse> {
    // Check amount
    if req.amount == 0 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Zero amount".to_string()),
        }));
    }

    // Parse mint
    let mint = match bs58::decode(&req.mint).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Bad mint".to_string()),
            })),
        },
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Bad mint format".to_string()),
        })),
    };

    // Parse destination
    let destination = match bs58::decode(&req.destination).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Bad destination".to_string()),
            })),
        },
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Bad destination format".to_string()),
        })),
    };

    // Fresh authority
    let authority = Keypair::new();

    // Build instruction
    let mint_ix = token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority.pubkey(),
        &[],
        req.amount,
    ).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!("Mint failed: {}", e))
    })?;

    // Pack response
    let response = ApiResponse {
        success: true,
        data: Some(MintTokenResponse {
            program_id: mint_ix.program_id.to_string(),
            accounts: mint_ix.accounts.iter().map(|acc| AccountInfo {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            }).collect(),
            instruction_data: base64::encode(&mint_ix.data),
        }),
        error: None,
    };

    Ok(HttpResponse::Ok().json(response))
}

// Sign message
async fn sign_message(req: web::Json<SignMessageRequest>) -> Result<HttpResponse> {
    // Parse private key
    let secret = match bs58::decode(&req.private_key).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Bad private key".to_string()),
        })),
    };

    // Build keypair
    let keypair = match Keypair::from_bytes(&secret) {
        Ok(kp) => kp,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Invalid private key".to_string()),
        })),
    };

    // Sign message
    let signature = keypair.sign_message(req.message.as_bytes());

    // Pack response
    let response = ApiResponse {
        success: true,
        data: Some(SignMessageResponse {
            signature: bs58::encode(signature.as_ref()).into_string(),
        }),
        error: None,
    };

    Ok(HttpResponse::Ok().json(response))
}

// Verify signature
async fn verify_message(req: web::Json<VerifyMessageRequest>) -> Result<HttpResponse> {
    // Parse public key
    let pubkey = match bs58::decode(&req.public_key).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Bad public key".to_string()),
            })),
        },
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Bad public key format".to_string()),
        })),
    };

    // Parse signature
    let signature = match bs58::decode(&req.signature).into_vec() {
        Ok(bytes) => match Signature::try_from(bytes.as_slice()) {
            Ok(sig) => sig,
            Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Bad signature".to_string()),
            })),
        },
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Bad signature format".to_string()),
        })),
    };

    // Verify signature
    let is_valid = signature.verify(pubkey.as_ref(), req.message.as_bytes());

    // Pack response
    let response = ApiResponse {
        success: true,
        data: Some(VerifyMessageResponse {
            is_valid,
        }),
        error: None,
    };

    Ok(HttpResponse::Ok().json(response))
}

// Send SOL
async fn send_sol(req: web::Json<SendSolRequest>) -> Result<HttpResponse> {
    // Check amount
    if req.amount == 0 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Zero amount".to_string()),
        }));
    }

    // Parse sender
    let from = match bs58::decode(&req.from).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Bad sender".to_string()),
            })),
        },
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Bad sender format".to_string()),
        })),
    };

    // Parse recipient
    let to = match bs58::decode(&req.to).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Bad recipient".to_string()),
            })),
        },
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Bad recipient format".to_string()),
        })),
    };

    // Build transfer
    let transfer_ix = system_instruction::transfer(&from, &to, req.amount);

    // Pack response
    let response = ApiResponse {
        success: true,
        data: Some(SendSolResponse {
            program_id: transfer_ix.program_id.to_string(),
            accounts: transfer_ix.accounts.iter().map(|acc| AccountInfo {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            }).collect(),
            instruction_data: base64::encode(&transfer_ix.data),
        }),
        error: None,
    };

    Ok(HttpResponse::Ok().json(response))
}

// Send tokens
async fn send_token(req: web::Json<SendTokenRequest>) -> Result<HttpResponse> {
    // Check amount
    if req.amount == 0 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Zero amount".to_string()),
        }));
    }

    // Parse recipient
    let destination = match bs58::decode(&req.destination).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Bad recipient".to_string()),
            })),
        },
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Bad recipient format".to_string()),
        })),
    };

    // Parse token
    let mint = match bs58::decode(&req.mint).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Bad token".to_string()),
            })),
        },
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Bad token format".to_string()),
        })),
    };

    // Parse sender
    let owner = match bs58::decode(&req.owner).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Bad sender".to_string()),
            })),
        },
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Bad sender format".to_string()),
        })),
    };

    // Get sender ATA
    let source = spl_associated_token_account::get_associated_token_address(
        &owner,
        &mint,
    );

    // Get recipient ATA
    let dest = spl_associated_token_account::get_associated_token_address(
        &destination,
        &mint,
    );

    // Build transfer
    let transfer_ix = token_instruction::transfer(
        &spl_token::id(),
        &source,
        &dest,
        &owner,
        &[],
        req.amount,
    ).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!("Transfer failed: {}", e))
    })?;

    // Pack response
    let response = ApiResponse {
        success: true,
        data: Some(SendTokenResponse {
            program_id: transfer_ix.program_id.to_string(),
            accounts: transfer_ix.accounts.iter().map(|acc| AccountInfo {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            }).collect(),
            instruction_data: base64::encode(&transfer_ix.data),
        }),
        error: None,
    };

    Ok(HttpResponse::Ok().json(response))
}

// Start server
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Get port
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let bind_address = format!("0.0.0.0:{}", port);
    
    // Log startup
    println!("Starting server on {}", bind_address);
    
    // Configure routes
    HttpServer::new(|| {
        App::new()
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
            .route("/token/mint", web::post().to(mint_token))
            .route("/message/sign", web::post().to(sign_message))
            .route("/message/verify", web::post().to(verify_message))
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
    })
    .bind(bind_address)?
    .run()
    .await
}
