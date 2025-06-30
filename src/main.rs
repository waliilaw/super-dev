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
    mintAuthority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize, Serialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize, Serialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Deserialize, Serialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Deserialize, Serialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
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
    pubkey: String,
    message: String,
}

#[derive(Serialize, Deserialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Serialize, Deserialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Serialize, Deserialize)]
struct SendTokenAccountInfo {
    pubkey: String,
    isSigner: bool,
}

#[derive(Serialize, Deserialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<SendTokenAccountInfo>,
    instruction_data: String,
}

// Generate keypair
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

// Create token
async fn create_token(req: web::Json<CreateTokenRequest>) -> Result<HttpResponse> {
    // Parse mint authority
    let mint_authority = match bs58::decode(&req.mintAuthority).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
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

    // Parse mint
    let mint = match bs58::decode(&req.mint).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
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

    let create_ix = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None,
        req.decimals,
    ).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!("Failed to create token: {}", e))
    })?;

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

// Mint token
async fn mint_token(req: web::Json<MintTokenRequest>) -> Result<HttpResponse> {
    if req.amount == 0 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Amount must be greater than 0".to_string()),
        }));
    }

    let mint = match bs58::decode(&req.mint).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
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
            Ok(pk) => pk,
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
            Ok(pk) => pk,
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

    let mint_ix = token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        req.amount,
    ).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!("Failed to create mint instruction: {}", e))
    })?;

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
    if req.message.is_empty() || req.secret.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        }));
    }

    let secret = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Invalid secret key format".to_string()),
        })),
    };

    let keypair = match Keypair::from_bytes(&secret) {
        Ok(kp) => kp,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Invalid secret key".to_string()),
        })),
    };

    let signature = keypair.sign_message(req.message.as_bytes());

    let response = ApiResponse {
        success: true,
        data: Some(SignMessageResponse {
            signature: BASE64.encode(signature.as_ref()),
            pubkey: keypair.pubkey().to_string(),
            message: req.message.clone(),
        }),
        error: None,
    };

    Ok(HttpResponse::Ok().json(response))
}

// Verify message
async fn verify_message(req: web::Json<VerifyMessageRequest>) -> Result<HttpResponse> {
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

    let valid = signature.verify(pubkey.as_ref(), req.message.as_bytes());

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

// Send SOL
async fn send_sol(req: web::Json<SendSolRequest>) -> Result<HttpResponse> {
    if req.lamports == 0 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Amount must be greater than 0".to_string()),
        }));
    }

    let from = match bs58::decode(&req.from).into_vec() {
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

    let to = match bs58::decode(&req.to).into_vec() {
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

    let transfer_ix = system_instruction::transfer(&from, &to, req.lamports);

    let response = ApiResponse {
        success: true,
        data: Some(SendSolResponse {
            program_id: transfer_ix.program_id.to_string(),
            accounts: transfer_ix.accounts.iter()
                .map(|acc| acc.pubkey.to_string())
                .collect(),
            instruction_data: BASE64.encode(&transfer_ix.data),
        }),
        error: None,
    };

    Ok(HttpResponse::Ok().json(response))
}

// Send tokens
async fn send_token(req: web::Json<SendTokenRequest>) -> Result<HttpResponse> {
    if req.amount == 0 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Amount must be greater than 0".to_string()),
        }));
    }

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

    let source = get_associated_token_address(
        &owner,
        &mint,
    );

    let dest = get_associated_token_address(
        &destination,
        &mint,
    );

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
            accounts: transfer_ix.accounts.iter().map(|acc| SendTokenAccountInfo {
                pubkey: acc.pubkey.to_string(),
                isSigner: acc.is_signer,
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
        assert!(!keypair.pubkey.is_empty());
        assert!(!keypair.secret.is_empty());
    }

    // Test token creation
    #[actix_web::test]
    async fn test_create_token() {
        let app = test::init_service(
            App::new().service(web::resource("/token/create").route(web::post().to(create_token)))
        ).await;

        let req = test::TestRequest::post()
            .uri("/token/create")
            .set_json(CreateTokenRequest {
                mintAuthority: "".to_string(),
                mint: "".to_string(),
                decimals: 9,
            })
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
                authority: "".to_string(),
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
                secret: bs58::encode(&keypair.to_bytes()).into_string(),
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
                pubkey: keypair.pubkey().to_string(),
            })
            .to_request();

        let resp: ApiResponse<VerifyMessageResponse> = test::call_and_read_body_json(&app, req).await;

        assert!(resp.success);
        assert!(resp.data.is_some());
        assert!(resp.error.is_none());

        let verify_resp = resp.data.unwrap();
        assert!(verify_resp.valid);
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
                lamports: 1000000,
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
                authority: "".to_string(),
                amount: 0,
            })
            .to_request();

        let resp: ApiResponse<MintTokenResponse> = test::call_and_read_body_json(&app, req).await;

        assert!(!resp.success);
        assert!(resp.data.is_none());
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap(), "Amount must be greater than 0".to_string());
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
                authority: "".to_string(),
                amount: 1000000,
            })
            .to_request();

        let resp: ApiResponse<MintTokenResponse> = test::call_and_read_body_json(&app, req).await;

        assert!(!resp.success);
        assert!(resp.data.is_none());
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap(), "Invalid mint base58 string".to_string());
    }
}
