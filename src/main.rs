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
use spl_associated_token_account::get_associated_token_address;
use std::env;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

// Request shapes
#[derive(Deserialize, Serialize)]
struct CreateTokenRequest {
    decimals: u8,
}

#[derive(Deserialize, Serialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    amount: u64,
}

#[derive(Deserialize, Serialize)]
struct SignMessageRequest {
    message: String,
    private_key: String,
}

#[derive(Deserialize, Serialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    public_key: String,
}

#[derive(Deserialize, Serialize)]
struct SendSolRequest {
    to: String,
    from: String,
    amount: u64,
}

#[derive(Deserialize, Serialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

// Response shapes
#[derive(Serialize, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct KeypairResponse {
    public_key: String,
    private_key: String,
}

#[derive(Serialize, Deserialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize, Deserialize)]
struct CreateTokenResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize, Deserialize)]
struct MintTokenResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize, Deserialize)]
struct SignMessageResponse {
    signature: String,
}

#[derive(Serialize, Deserialize)]
struct VerifyMessageResponse {
    is_valid: bool,
}

#[derive(Serialize, Deserialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize, Deserialize)]
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
            private_key: bs58::encode(keypair.secret()).into_string(),
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
            instruction_data: BASE64.encode(&create_ix.data),
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
            instruction_data: BASE64.encode(&mint_ix.data),
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
            instruction_data: BASE64.encode(&transfer_ix.data),
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
    let source = get_associated_token_address(
        &owner,
        &mint,
    );

    // Get recipient ATA
    let dest = get_associated_token_address(
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
            instruction_data: BASE64.encode(&transfer_ix.data),
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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};

    // Test keypair generation
    #[actix_web::test]
    async fn test_generate_keypair() {
        let app = test::init_service(
            App::new().service(web::resource("/keypair").route(web::post().to(generate_keypair)))
        ).await;

        let req = test::TestRequest::post().uri("/keypair").to_request();
        let resp: ApiResponse<KeypairResponse> = test::call_and_read_body_json(&app, req).await;

        assert!(resp.success);
        assert!(resp.data.is_some());
        assert!(resp.error.is_none());

        let keypair = resp.data.unwrap();
        assert!(!keypair.public_key.is_empty());
        assert!(!keypair.private_key.is_empty());
    }

    // Test token creation
    #[actix_web::test]
    async fn test_create_token() {
        let app = test::init_service(
            App::new().service(web::resource("/token/create").route(web::post().to(create_token)))
        ).await;

        let req = test::TestRequest::post()
            .uri("/token/create")
            .set_json(CreateTokenRequest { decimals: 9 })
            .to_request();

        let resp: ApiResponse<CreateTokenResponse> = test::call_and_read_body_json(&app, req).await;

        assert!(resp.success);
        assert!(resp.data.is_some());
        assert!(resp.error.is_none());

        let token = resp.data.unwrap();
        assert!(!token.program_id.is_empty());
        assert!(!token.accounts.is_empty());
        assert!(!token.instruction_data.is_empty());
    }

    // Test token minting
    #[actix_web::test]
    async fn test_mint_token() {
        let app = test::init_service(
            App::new().service(web::resource("/token/mint").route(web::post().to(mint_token)))
        ).await;

        // Generate a valid keypair for testing
        let mint_kp = Keypair::new();
        let dest_kp = Keypair::new();

        let req = test::TestRequest::post()
            .uri("/token/mint")
            .set_json(MintTokenRequest {
                mint: mint_kp.pubkey().to_string(),
                destination: dest_kp.pubkey().to_string(),
                amount: 1000000,
            })
            .to_request();

        let resp: ApiResponse<MintTokenResponse> = test::call_and_read_body_json(&app, req).await;

        assert!(resp.success);
        assert!(resp.data.is_some());
        assert!(resp.error.is_none());

        let mint_resp = resp.data.unwrap();
        assert!(!mint_resp.program_id.is_empty());
        assert!(!mint_resp.accounts.is_empty());
        assert!(!mint_resp.instruction_data.is_empty());
    }

    // Test message signing
    #[actix_web::test]
    async fn test_sign_message() {
        let app = test::init_service(
            App::new().service(web::resource("/message/sign").route(web::post().to(sign_message)))
        ).await;

        let keypair = Keypair::new();
        let message = "Hello, Solana!";

        let req = test::TestRequest::post()
            .uri("/message/sign")
            .set_json(SignMessageRequest {
                message: message.to_string(),
                private_key: bs58::encode(&keypair.to_bytes()).into_string(),
            })
            .to_request();

        let resp: ApiResponse<SignMessageResponse> = test::call_and_read_body_json(&app, req).await;

        assert!(resp.success, "Failed to sign message: {:?}", resp.error);
        assert!(resp.data.is_some());
        assert!(resp.error.is_none());

        let sign_resp = resp.data.unwrap();
        assert!(!sign_resp.signature.is_empty());
    }

    // Test message verification
    #[actix_web::test]
    async fn test_verify_message() {
        let app = test::init_service(
            App::new().service(web::resource("/message/verify").route(web::post().to(verify_message)))
        ).await;

        let keypair = Keypair::new();
        let message = "Hello, Solana!";
        let signature = keypair.sign_message(message.as_bytes());

        let req = test::TestRequest::post()
            .uri("/message/verify")
            .set_json(VerifyMessageRequest {
                message: message.to_string(),
                signature: bs58::encode(signature.as_ref()).into_string(),
                public_key: keypair.pubkey().to_string(),
            })
            .to_request();

        let resp: ApiResponse<VerifyMessageResponse> = test::call_and_read_body_json(&app, req).await;

        assert!(resp.success);
        assert!(resp.data.is_some());
        assert!(resp.error.is_none());

        let verify_resp = resp.data.unwrap();
        assert!(verify_resp.is_valid);
    }

    // Test SOL transfer
    #[actix_web::test]
    async fn test_send_sol() {
        let app = test::init_service(
            App::new().service(web::resource("/send/sol").route(web::post().to(send_sol)))
        ).await;

        let from_kp = Keypair::new();
        let to_kp = Keypair::new();

        let req = test::TestRequest::post()
            .uri("/send/sol")
            .set_json(SendSolRequest {
                from: from_kp.pubkey().to_string(),
                to: to_kp.pubkey().to_string(),
                amount: 1000000,
            })
            .to_request();

        let resp: ApiResponse<SendSolResponse> = test::call_and_read_body_json(&app, req).await;

        assert!(resp.success);
        assert!(resp.data.is_some());
        assert!(resp.error.is_none());

        let transfer_resp = resp.data.unwrap();
        assert!(!transfer_resp.program_id.is_empty());
        assert!(!transfer_resp.accounts.is_empty());
        assert!(!transfer_resp.instruction_data.is_empty());
    }

    // Test token transfer
    #[actix_web::test]
    async fn test_send_token() {
        let app = test::init_service(
            App::new().service(web::resource("/send/token").route(web::post().to(send_token)))
        ).await;

        let owner_kp = Keypair::new();
        let dest_kp = Keypair::new();
        let mint_kp = Keypair::new();

        let req = test::TestRequest::post()
            .uri("/send/token")
            .set_json(SendTokenRequest {
                destination: dest_kp.pubkey().to_string(),
                mint: mint_kp.pubkey().to_string(),
                owner: owner_kp.pubkey().to_string(),
                amount: 1000000,
            })
            .to_request();

        let resp: ApiResponse<SendTokenResponse> = test::call_and_read_body_json(&app, req).await;

        assert!(resp.success);
        assert!(resp.data.is_some());
        assert!(resp.error.is_none());

        let transfer_resp = resp.data.unwrap();
        assert!(!transfer_resp.program_id.is_empty());
        assert!(!transfer_resp.accounts.is_empty());
        assert!(!transfer_resp.instruction_data.is_empty());
    }

    // Test error cases
    #[actix_web::test]
    async fn test_mint_token_zero_amount() {
        let app = test::init_service(
            App::new().service(web::resource("/token/mint").route(web::post().to(mint_token)))
        ).await;

        let mint_kp = Keypair::new();
        let dest_kp = Keypair::new();

        let req = test::TestRequest::post()
            .uri("/token/mint")
            .set_json(MintTokenRequest {
                mint: mint_kp.pubkey().to_string(),
                destination: dest_kp.pubkey().to_string(),
                amount: 0,
            })
            .to_request();

        let resp: ApiResponse<MintTokenResponse> = test::call_and_read_body_json(&app, req).await;

        assert!(!resp.success);
        assert!(resp.data.is_none());
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap(), "Zero amount".to_string());
    }

    #[actix_web::test]
    async fn test_mint_token_invalid_address() {
        let app = test::init_service(
            App::new().service(web::resource("/token/mint").route(web::post().to(mint_token)))
        ).await;

        let dest_kp = Keypair::new();

        let req = test::TestRequest::post()
            .uri("/token/mint")
            .set_json(MintTokenRequest {
                mint: "invalid_address".to_string(),
                destination: dest_kp.pubkey().to_string(),
                amount: 1000000,
            })
            .to_request();

        let resp: ApiResponse<MintTokenResponse> = test::call_and_read_body_json(&app, req).await;

        assert!(!resp.success);
        assert!(resp.data.is_none());
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap(), "Bad mint format".to_string());
    }
}
