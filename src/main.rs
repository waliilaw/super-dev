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

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct SendTokenResponse {
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

async fn verify_message(req: web::Json<VerifyMessageRequest>) -> Result<HttpResponse> {
    // Validate request fields
    if req.message.is_empty() || req.signature.is_empty() || req.pubkey.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        }));
    }

    // Decode public key
    let pubkey = match bs58::decode(&req.pubkey).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid public key".to_string()),
            })),
        },
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Invalid public key format".to_string()),
        })),
    };

    // Decode signature from base64
    let signature_bytes = match base64::decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Invalid signature format".to_string()),
        })),
    };

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Invalid signature".to_string()),
        })),
    };

    // Verify the signature
    let message_bytes = req.message.as_bytes();
    let valid = signature.verify(pubkey.as_ref(), message_bytes);

    let response = ApiResponse {
        success: true,
        data: Some(VerifyMessageResponse {
            valid,
            message: req.message.clone(),
            pubkey: req.pubkey.clone(),
        }),
        error: None,
    };

    Ok(HttpResponse::Ok().json(response))
}

async fn send_sol(req: web::Json<SendSolRequest>) -> Result<HttpResponse> {
    // Validate lamports amount (must be greater than 0)
    if req.lamports == 0 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Amount must be greater than 0".to_string()),
        }));
    }

    // Parse from address
    let from_pubkey = match bs58::decode(&req.from).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid sender address".to_string()),
            })),
        },
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Invalid sender address format".to_string()),
        })),
    };

    // Parse to address
    let to_pubkey = match bs58::decode(&req.to).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid recipient address".to_string()),
            })),
        },
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Invalid recipient address format".to_string()),
        })),
    };

    // Create transfer instruction
    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, req.lamports);

    let response = ApiResponse {
        success: true,
        data: Some(SendSolResponse {
            program_id: instruction.program_id.to_string(),
            accounts: instruction.accounts.iter()
                .map(|acc| acc.pubkey.to_string())
                .collect(),
            instruction_data: base64::encode(&instruction.data),
        }),
        error: None,
    };

    Ok(HttpResponse::Ok().json(response))
}

async fn send_token(req: web::Json<SendTokenRequest>) -> Result<HttpResponse> {
    // Validate amount
    if req.amount == 0 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Amount must be greater than 0".to_string()),
        }));
    }

    // Parse destination address
    let destination = match bs58::decode(&req.destination).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid destination address".to_string()),
            })),
        },
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Invalid destination address format".to_string()),
        })),
    };

    // Parse mint address
    let mint = match bs58::decode(&req.mint).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint address".to_string()),
            })),
        },
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Invalid mint address format".to_string()),
        })),
    };

    // Parse owner address
    let owner = match bs58::decode(&req.owner).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid owner address".to_string()),
            })),
        },
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Invalid owner address format".to_string()),
        })),
    };

    // Get source token account (owner's ATA)
    let source = spl_associated_token_account::get_associated_token_address(
        &owner,
        &mint,
    );

    // Get destination token account (destination's ATA)
    let dest = spl_associated_token_account::get_associated_token_address(
        &destination,
        &mint,
    );

    // Create transfer instruction
    let transfer_ix = token_instruction::transfer(
        &spl_token::id(),
        &source,
        &dest,
        &owner,
        &[],
        req.amount,
    ).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!("Failed to create transfer instruction: {}", e))
    })?;

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
            .route("/message/verify", web::post().to(verify_message))
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
    })
    .bind(bind_address)?
    .run()
    .await
}
