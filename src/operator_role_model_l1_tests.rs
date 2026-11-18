//! Operator Role Model V2 L1 closure tests.
//!
//! This module is intentionally kept at the crate root so the L1 test suite has
//! a single searchable target for the Operator Role Model V2 acceptance closure:
//! `operator_role_model_l1_tests`.
//!
//! The tests below exercise the L1 operator/worker/evidence and validator-transition
//! paths directly from this crate-level closure target. A few source anchors remain
//! as regression pins to private runtime harnesses that cannot be called here without
//! weakening module boundaries; they are supplemental, not substitutes for the direct
//! assertions in this file.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};

fn assert_source_contains(source_name: &str, source: &str, needle: &str) {
    assert!(
        source.contains(needle),
        "operator_role_model_l1_tests regression anchor missing `{needle}` in {source_name}"
    );
}

fn blockchain_source() -> &'static str {
    include_str!("blockchain.rs")
}

fn evidence_source() -> &'static str {
    include_str!("e2_worker_evidence.rs")
}

fn governance_source() -> &'static str {
    include_str!("governance.rs")
}

fn test_key(seed: u8) -> (ed25519_dalek::SigningKey, String, String) {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let pk_b64 = STANDARD.encode(sk.verifying_key().to_bytes());
    let pk_hex = crate::keyfmt::pk_hex_from_any(&pk_b64).expect("test key to hex");
    (sk, pk_b64, pk_hex)
}

fn self_register_payload(
    worker_sk: &ed25519_dalek::SigningKey,
    worker_pk: &str,
    operator_pk: &str,
    genesis_hash: &str,
) -> crate::compute_contract::E2WorkerSelfRegistrationPayloadV1 {
    let mut payload = crate::compute_contract::E2WorkerSelfRegistrationPayloadV1 {
        format_version: crate::compute_contract::E2_WORKER_SELF_REGISTER_PAYLOAD_VERSION_V1
            .to_string(),
        worker_node_pubkey: worker_pk.to_string(),
        operator_wallet_pubkey: operator_pk.to_string(),
        worker_signature: String::new(),
        capabilities_commitment_hash: "c".repeat(64),
        runtime_class: "native-v1".to_string(),
        chain_id: crate::chain_identity::chain_id().to_string(),
        genesis_hash: genesis_hash.to_string(),
        region: Some("eu-west-1".to_string()),
        country: Some("IT".to_string()),
    };
    payload.worker_signature = crate::crypto::sign_ds_b64(
        worker_sk,
        crate::compute_contract::E2_WORKER_SELF_REGISTER_SIGNATURE_CONTEXT_V1,
        &crate::compute_contract::e2_worker_self_registration_signing_bytes_v1(&payload)
            .expect("self-register signing bytes"),
    );
    payload
}

fn self_register_tx(
    payload: &crate::compute_contract::E2WorkerSelfRegistrationPayloadV1,
    sender_sk: &ed25519_dalek::SigningKey,
    sender_pk: &str,
    nonce: u64,
) -> crate::transaction::Transaction {
    let memo = serde_json::json!({
        "v": 1,
        "op": crate::compute_contract::E2_WORKER_SELF_REGISTER_OP_V1,
        "format_version": payload.format_version.clone(),
        "worker_node_pubkey": payload.worker_node_pubkey.clone(),
        "operator_wallet_pubkey": payload.operator_wallet_pubkey.clone(),
        "worker_signature": payload.worker_signature.clone(),
        "capabilities_commitment_hash": payload.capabilities_commitment_hash.clone(),
        "runtime_class": payload.runtime_class.clone(),
        "chain_id": payload.chain_id.clone(),
        "genesis_hash": payload.genesis_hash.clone(),
        "region": payload.region.clone(),
        "country": payload.country.clone(),
    })
    .to_string();

    let signing_payload = crate::wallet::TransactionPayload {
        network_id: crate::chain_identity::network_id().to_string(),
        from: sender_pk.to_string(),
        to: crate::compute_contract::COMPUTE_RECEIVER.to_string(),
        amount: 0,
        max_fee_per_tx: 1_000_000,
        nonce,
        memo: Some(memo.clone()),
    };
    let signing_string = crate::wallet::canonical_signing_string(&signing_payload);
    let sig = sender_sk.sign(signing_string.as_bytes());

    crate::transaction::Transaction::new(
        sender_pk.to_string(),
        crate::compute_contract::COMPUTE_RECEIVER.to_string(),
        0,
        nonce,
        1_000_000,
        STANDARD.encode(sig.to_bytes()),
        false,
        Some(memo),
    )
}

struct StandardEvidenceFixtureV1 {
    chain: crate::Blockchain,
    worker_pk_b64: String,
    worker_hex: String,
    operator_pk_b64: String,
    operator_hex: String,
    payer_pk_b64: String,
    attester_sk: ed25519_dalek::SigningKey,
    attester_pk_b64: String,
    order_id: String,
    result_hash: String,
    receipt_hash: String,
}

fn signed_compute_tx(
    sender_sk: &ed25519_dalek::SigningKey,
    sender_pk_b64: &str,
    amount: u64,
    nonce: u64,
    memo: String,
) -> crate::transaction::Transaction {
    let max_fee_per_tx = 1_000_000;
    let payload = crate::wallet::TransactionPayload {
        network_id: crate::chain_identity::network_id().to_string(),
        from: sender_pk_b64.to_string(),
        to: crate::compute_contract::COMPUTE_RECEIVER.to_string(),
        amount,
        max_fee_per_tx,
        nonce,
        memo: Some(memo.clone()),
    };
    let signing_string = crate::wallet::canonical_signing_string(&payload);
    let sig = sender_sk.sign(signing_string.as_bytes());
    crate::transaction::Transaction::new(
        sender_pk_b64.to_string(),
        crate::compute_contract::COMPUTE_RECEIVER.to_string(),
        amount,
        nonce,
        max_fee_per_tx,
        STANDARD.encode(sig.to_bytes()),
        false,
        Some(memo),
    )
}

fn push_e2_fixture_block(
    chain: &mut crate::Blockchain,
    index: u64,
    txs: Vec<crate::transaction::Transaction>,
) -> String {
    let prev_hash = chain
        .chain
        .last()
        .map(|b| b.hash.clone())
        .unwrap_or_else(|| "00".repeat(32));
    let mut block = chain.create_block_dummy();
    block.index = index;
    block.previous_hash = prev_hash;
    block.hash = format!("{:064x}", 0xE200u64 + index);
    block.transactions = txs;
    block.tx_root = crate::merkle::tx_root_hex_from_transactions(&block.transactions);
    chain.chain.push(block);
    format!("{:064x}", 0xE200u64 + index)
}

fn sign_e2_standard_evidence(
    mut ev: crate::e2_worker_evidence::E2WorkerExecutionEvidenceV2,
    attester_sk: &ed25519_dalek::SigningKey,
) -> crate::e2_worker_evidence::E2WorkerExecutionEvidenceV2 {
    ev.evidence_hash = crate::e2_worker_evidence::expected_e2_worker_evidence_id_v2(&ev);
    let sig =
        attester_sk.sign(&crate::e2_worker_evidence::e2_worker_evidence_signing_bytes_v2(&ev));
    ev.signature = STANDARD.encode(sig.to_bytes());
    ev
}

fn evidence_submit_tx(
    attester_sk: &ed25519_dalek::SigningKey,
    attester_pk_b64: &str,
    ev: crate::e2_worker_evidence::E2WorkerExecutionEvidenceV2,
    nonce: u64,
) -> crate::transaction::Transaction {
    let memo = serde_json::json!({
        "v": 1,
        "op": crate::compute_contract::E2_WORKER_EVIDENCE_SUBMIT_OP_V1,
        "format_version": crate::compute_contract::E2_WORKER_EVIDENCE_SUBMIT_PAYLOAD_VERSION_V1,
        "evidence": crate::e2_worker_evidence::E2WorkerExecutionEvidenceAnyV1::V2(ev),
    })
    .to_string();
    signed_compute_tx(attester_sk, attester_pk_b64, 0, nonce, memo)
}

fn setup_standard_evidence_fixture(
    completed: bool,
    bind_worker: bool,
) -> StandardEvidenceFixtureV1 {
    let mut chain = crate::Blockchain::new();
    chain.genesis_hash = "77".repeat(32);

    let (_worker_sk, worker_pk_b64, worker_hex) = test_key(0x71);
    let (_operator_sk, operator_pk_b64, operator_hex) = test_key(0x72);
    let (payer_sk, payer_pk_b64, _payer_hex) = test_key(0x73);
    let (attester_sk, attester_pk_b64, _attester_hex) = test_key(0x74);

    {
        let gov = chain.governance.as_mut().expect("governance expected");
        gov.validator_set.entries = vec![crate::governance::ValidatorEntry {
            pub_key: attester_pk_b64.clone(),
            alias: Some("attester-a".to_string()),
            weight: 1,
        }];
    }
    if bind_worker {
        chain
            .apply_e2_worker_operator_binding_from_governance_v1(&worker_hex, &operator_hex, 0)
            .expect("worker/operator binding");
    }

    let create_memo = serde_json::json!({
        "v": 1,
        "op": "order_create",
        "job_spec_hash": "11".repeat(32),
        "max_time_ms": 10_000,
        "job_kind": "hash_sha256_v1",
    })
    .to_string();
    let create_tx = signed_compute_tx(&payer_sk, &payer_pk_b64, 1_000, 1, create_memo);
    let order_id = create_tx.hash.clone();
    push_e2_fixture_block(&mut chain, 1, vec![create_tx]);

    let claim_memo = serde_json::json!({
        "v": 1,
        "op": "order_claim",
        "order_id": order_id.clone(),
    })
    .to_string();
    let worker_sk = ed25519_dalek::SigningKey::from_bytes(&[0x71; 32]);
    let claim_tx = signed_compute_tx(&worker_sk, &worker_pk_b64, 0, 1, claim_memo);
    push_e2_fixture_block(&mut chain, 2, vec![claim_tx]);

    let result_hash = "22".repeat(32);
    let receipt_hash = "33".repeat(32);
    let terminal_memo = if completed {
        serde_json::json!({
            "v": 1,
            "op": "order_complete",
            "order_id": order_id.clone(),
            "result_hash": result_hash.clone(),
            "exit_code": 0,
            "receipt_hash": receipt_hash.clone(),
        })
    } else {
        serde_json::json!({
            "v": 1,
            "op": "order_fail",
            "order_id": order_id.clone(),
            "reason": "timeout",
            "receipt_hash": receipt_hash.clone(),
        })
    }
    .to_string();
    let terminal_tx = signed_compute_tx(&worker_sk, &worker_pk_b64, 0, 2, terminal_memo);
    let finalized_hash = push_e2_fixture_block(&mut chain, 3, vec![terminal_tx]);
    chain.set_test_finality_meta(3, finalized_hash.clone(), 3, 0, finalized_hash);
    let required_job_kind_activation_height = chain
        .governance
        .as_ref()
        .map(|g| g.params.e2_worker_admission_activation_height)
        .unwrap_or(0);
    chain.compute_order_state_store =
        crate::compute_contract::compute_order_state_store_rebuild_from_blocks_v1(
            &chain.chain,
            required_job_kind_activation_height,
        )
        .expect("operator role L1 fixture compute order state store rebuild");

    StandardEvidenceFixtureV1 {
        chain,
        worker_pk_b64,
        worker_hex,
        operator_pk_b64,
        operator_hex,
        payer_pk_b64,
        attester_sk,
        attester_pk_b64,
        order_id,
        result_hash,
        receipt_hash,
    }
}

fn evidence_for_standard_fixture(
    fixture: &StandardEvidenceFixtureV1,
    completed: bool,
    nonce_byte: u8,
) -> crate::e2_worker_evidence::E2WorkerExecutionEvidenceV2 {
    sign_e2_standard_evidence(
        crate::e2_worker_evidence::E2WorkerExecutionEvidenceV2 {
            format_version: crate::e2_worker_evidence::E2_WORKER_EVIDENCE_FORMAT_VERSION_V2
                .to_string(),
            chain_id: crate::chain_identity::network_id().to_string(),
            genesis_hash: fixture.chain.genesis_hash.clone(),
            e2_contract_version: crate::version::E2_CONTRACT_VERSION.to_string(),
            order_id: fixture.order_id.clone(),
            job_id: format!("job-operator-role-l1-{nonce_byte}"),
            job_kind: "hash_sha256_v1".to_string(),
            worker_node_pubkey: fixture.worker_pk_b64.clone(),
            operator_wallet_pubkey: fixture.operator_pk_b64.clone(),
            payer_wallet: fixture.payer_pk_b64.clone(),
            order_created_height: 1,
            order_claimed_height: 2,
            order_terminal_height: 3,
            result_hash: if completed {
                Some(fixture.result_hash.clone())
            } else {
                None
            },
            artifact_root_hash: None,
            receipt_hash: Some(fixture.receipt_hash.clone()),
            execution_status: if completed { "COMPLETED" } else { "FAILED" }.to_string(),
            failure_class: if completed {
                crate::e2_worker_evidence::FAILURE_SUCCESS
            } else {
                crate::e2_worker_evidence::FAILURE_TIMEOUT
            }
            .to_string(),
            fault_domain: crate::e2_worker_evidence::FAULT_WORKER.to_string(),
            penalty_effect: if completed {
                crate::e2_worker_evidence::EFFECT_POSITIVE
            } else {
                crate::e2_worker_evidence::EFFECT_SOFT_PENALTY
            }
            .to_string(),
            worker_fault: !completed,
            verifier_verdict: if completed {
                crate::e2_worker_evidence::VERDICT_ACCEPT_POSITIVE
            } else {
                crate::e2_worker_evidence::VERDICT_WORKER_PENALTY_CANDIDATE
            }
            .to_string(),
            taxonomy_version: crate::e2_worker_evidence::WORKER_PENALTY_TAXONOMY_VERSION_V1
                .to_string(),
            sla_ms: 100,
            max_time_ms: 10_000,
            coordinator_id: "coord-operator-role-l1".to_string(),
            attester_pubkey: fixture.attester_pk_b64.clone(),
            evidence_timestamp_ms: 500_000 + nonce_byte as u64,
            evidence_hash: String::new(),
            signature: String::new(),
        },
        &fixture.attester_sk,
    )
}

struct OperatorRoleL1TransitionFixtureV1 {
    gov: crate::governance::GovernanceState,
    council_sk: ed25519_dalek::SigningKey,
    validator_b_b64: String,
    validator_b_hex: String,
}

fn operator_l1_pk_b64(sk: &ed25519_dalek::SigningKey) -> String {
    STANDARD.encode(sk.verifying_key().to_bytes())
}

fn operator_l1_sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn operator_l1_council(pk_b64: &str) -> crate::governance::Council {
    crate::governance::Council {
        members: vec![pk_b64.to_string()],
        threshold: 1,
    }
}

fn operator_l1_validator(pk: &str, alias: &str) -> crate::governance::ValidatorEntry {
    crate::governance::ValidatorEntry {
        pub_key: pk.to_string(),
        alias: Some(alias.to_string()),
        weight: 1,
    }
}

fn setup_operator_l1_transition_fixture(
    validator_count: usize,
    min_active_validators: usize,
    min_finality_quorum: usize,
    cooldown_blocks: u64,
) -> OperatorRoleL1TransitionFixtureV1 {
    let council_sk = ed25519_dalek::SigningKey::from_bytes(&[0x81; 32]);
    let validator_b_sk = ed25519_dalek::SigningKey::from_bytes(&[0x82; 32]);
    let validator_c_sk = ed25519_dalek::SigningKey::from_bytes(&[0x83; 32]);
    let council_b64 = operator_l1_pk_b64(&council_sk);
    let validator_b_b64 = operator_l1_pk_b64(&validator_b_sk);
    let validator_c_b64 = operator_l1_pk_b64(&validator_c_sk);
    let council_hex = crate::keyfmt::pk_hex_from_any(&council_b64).expect("council hex");
    let validator_b_hex =
        crate::keyfmt::pk_hex_from_any(&validator_b_b64).expect("validator b hex");
    let validator_c_hex =
        crate::keyfmt::pk_hex_from_any(&validator_c_b64).expect("validator c hex");

    let mut params = crate::governance::GovernanceParams::default();
    params.validator_compute_transition_min_active_validators = min_active_validators;
    params.validator_compute_transition_min_finality_quorum = min_finality_quorum;
    params.validator_compute_transition_exit_cooldown_blocks = cooldown_blocks;
    params.validator_compute_transition_validator_quality_floor = 0;
    params.validator_compute_transition_max_finality_lag_blocks = 64;
    params.validator_compute_transition_max_recent_missed_slots = 64;

    let mut entries = vec![operator_l1_validator(&council_hex, "A")];
    if validator_count >= 2 {
        entries.push(operator_l1_validator(&validator_b_hex, "B"));
    }
    if validator_count >= 3 {
        entries.push(operator_l1_validator(&validator_c_hex, "C"));
    }

    let gov = crate::governance::GovernanceState::new(
        operator_l1_council(&council_b64),
        operator_l1_council(&council_b64),
        operator_l1_council(&council_b64),
        params,
        crate::governance::ValidatorSet {
            entries,
            version: 1,
        },
    );

    OperatorRoleL1TransitionFixtureV1 {
        gov,
        council_sk,
        validator_b_b64,
        validator_b_hex,
    }
}

fn operator_l1_transition_request_proposal(
    id_hex_suffix: &str,
    proposer_sk: &ed25519_dalek::SigningKey,
    validator_pub_key: &str,
    operator_wallet_pubkey: &str,
    created_at_height: u64,
    effective_height: u64,
    requested_at_height: Option<u64>,
) -> crate::governance::TxGovernanceProposal {
    let payload = crate::governance::ValidatorComputeTransitionRequestPayload {
        validator_pub_key: validator_pub_key.to_string(),
        operator_wallet_pubkey: operator_wallet_pubkey.to_string(),
        requested_compute_only: true,
        requested_at_height,
        reason: Some("operator-role-model-l1-tests".to_string()),
    };
    let mut proposal = crate::governance::TxGovernanceProposal {
        id: format!("operator-role-l1-govp-{id_hex_suffix}"),
        kind: crate::governance::GovProposalKind::RequestValidatorComputeTransition,
        payload: serde_json::to_vec(&payload).expect("transition request payload"),
        created_at_height,
        effective_height,
        proposer: operator_l1_pk_b64(proposer_sk),
        signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
        chain_id: crate::chain_identity::chain_id().to_string(),
        genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
        signature: String::new(),
    };
    let msg = crate::governance::proposal_signing_bytes_v1(
        &proposal,
        &crate::governance::GovernanceCouncilKind::Emergency,
    )
    .expect("transition proposal signing bytes");
    proposal.signature = STANDARD.encode(proposer_sk.sign(&msg).to_bytes());
    proposal
}

fn operator_l1_transition_cancel_proposal(
    id_hex_suffix: &str,
    proposer_sk: &ed25519_dalek::SigningKey,
    validator_pub_key: &str,
    operator_wallet_pubkey: &str,
    created_at_height: u64,
    effective_height: u64,
) -> crate::governance::TxGovernanceProposal {
    let payload = crate::governance::CancelValidatorComputeTransitionPayload {
        validator_pub_key: validator_pub_key.to_string(),
        operator_wallet_pubkey: operator_wallet_pubkey.to_string(),
        reason: Some("operator-role-model-l1-cancel-tests".to_string()),
    };
    let mut proposal = crate::governance::TxGovernanceProposal {
        id: format!("operator-role-l1-govp-{id_hex_suffix}"),
        kind: crate::governance::GovProposalKind::CancelValidatorComputeTransition,
        payload: serde_json::to_vec(&payload).expect("transition cancel payload"),
        created_at_height,
        effective_height,
        proposer: operator_l1_pk_b64(proposer_sk),
        signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
        chain_id: crate::chain_identity::chain_id().to_string(),
        genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
        signature: String::new(),
    };
    let msg = crate::governance::proposal_signing_bytes_v1(
        &proposal,
        &crate::governance::GovernanceCouncilKind::Emergency,
    )
    .expect("cancel proposal signing bytes");
    proposal.signature = STANDARD.encode(proposer_sk.sign(&msg).to_bytes());
    proposal
}

fn operator_l1_vote_for_proposal(
    proposal: &crate::governance::TxGovernanceProposal,
    voter_sk: &ed25519_dalek::SigningKey,
) -> crate::governance::TxGovernanceVote {
    let proposal_msg = crate::governance::proposal_signing_bytes_v1(
        proposal,
        &crate::governance::GovernanceCouncilKind::Emergency,
    )
    .expect("proposal hash signing bytes");
    let proposal_hash_hex = operator_l1_sha256_hex(&proposal_msg);
    let voter = operator_l1_pk_b64(voter_sk);
    let mut vote = crate::governance::TxGovernanceVote {
        proposal_id: proposal.id.clone(),
        proposal_hash_hex,
        voter,
        signature_domain: crate::governance::GOVERNANCE_SIGNATURE_DOMAIN_V2.to_string(),
        chain_id: crate::chain_identity::chain_id().to_string(),
        genesis_hash: crate::governance::governance_signature_genesis_hash_for_runtime_v1(),
        signature: String::new(),
    };
    let msg = crate::governance::vote_signing_bytes_for_tx_v1(&vote).expect("vote signing bytes");
    vote.signature = STANDARD.encode(voter_sk.sign(&msg).to_bytes());
    vote
}

fn apply_operator_l1_governance_proposal_at_finality(
    gov: &mut crate::governance::GovernanceState,
    height: u64,
    finalized_height: u64,
    proposal: crate::governance::TxGovernanceProposal,
    voter_sk: &ed25519_dalek::SigningKey,
) {
    let vote = operator_l1_vote_for_proposal(&proposal, voter_sk);
    gov.apply_block_governance_with_effects_at_finality(
        height,
        &[
            crate::governance::GovernanceTx::Proposal(proposal),
            crate::governance::GovernanceTx::Vote(vote),
        ],
        finalized_height,
    );
}

#[test]
fn self_registration_requires_operator_wallet_as_tx_sender() {
    let mut chain = crate::Blockchain::new();
    chain.genesis_hash = "11".repeat(32);
    let (worker_sk, worker_pk, _) = test_key(0x31);
    let (_operator_sk, operator_pk, _) = test_key(0x32);
    let (wrong_sender_sk, wrong_sender_pk, _) = test_key(0x33);
    let payload = self_register_payload(&worker_sk, &worker_pk, &operator_pk, &chain.genesis_hash);
    let tx = self_register_tx(&payload, &wrong_sender_sk, &wrong_sender_pk, 1);

    let err = chain
        .apply_e2_worker_self_registration_from_compute_tx_v1(&tx, 7)
        .expect_err("self-registration must require operator wallet as transaction sender");
    assert!(
        err.contains("sender_operator_mismatch"),
        "unexpected error: {err}"
    );

    let worker_hex = crate::keyfmt::pk_hex_from_any(&worker_pk).expect("worker hex");
    assert!(
        !chain
            .governance
            .as_ref()
            .expect("governance")
            .e2_worker_operator_bindings
            .contains_key(&worker_hex),
        "mismatched sender must not create a binding"
    );

    let src = blockchain_source();
    assert_source_contains(
        "src/blockchain.rs",
        src,
        "self_register_sender_operator_mismatch_rejected_before_apply_v1",
    );
    assert_source_contains("src/blockchain.rs", src, "sender_operator_mismatch");
    assert_source_contains("src/blockchain.rs", src, "operator_wallet_pubkey");
}

#[test]
fn worker_key_and_operator_wallet_are_distinct() {
    let mut chain = crate::Blockchain::new();
    let (_sk, pk_b64, _pk_hex) = test_key(0x34);
    let err = chain
        .apply_e2_worker_operator_binding_from_governance_v1(&pk_b64, &pk_b64, 0)
        .expect_err("worker key and operator wallet must be distinct identities");
    assert!(
        err.contains("requires_distinct_identities"),
        "unexpected error: {err}"
    );

    let src = evidence_source();
    assert_source_contains(
        "src/e2_worker_evidence.rs",
        src,
        "e2_worker_operator_binding_is_required_and_distinct",
    );
    assert_source_contains(
        "src/e2_worker_evidence.rs",
        src,
        "operator_wallet_must_be_distinct_from_worker_node",
    );
}

#[test]
fn binding_duplicate_same_pair_is_idempotent() {
    let mut chain = crate::Blockchain::new();
    let (_worker_sk, _worker_b64, worker_hex) = test_key(0x35);
    let (_operator_sk, _operator_b64, operator_hex) = test_key(0x36);

    chain
        .apply_e2_worker_operator_binding_from_governance_v1(&worker_hex, &operator_hex, 0)
        .expect("first binding apply");
    chain
        .apply_e2_worker_operator_binding_from_governance_v1(&worker_hex, &operator_hex, 9)
        .expect("duplicate same-pair binding is idempotent");

    let binding = chain
        .resolve_e2_worker_operator_binding_finalized_hex_v1(&worker_hex, 0)
        .expect("duplicate same-pair must preserve original finalized binding");
    assert_eq!(binding.worker_node_pubkey, worker_hex);
    assert_eq!(binding.operator_wallet_pubkey, operator_hex);
    assert_eq!(binding.bound_at_height, 0);

    let src = evidence_source();
    assert_source_contains(
        "src/e2_worker_evidence.rs",
        src,
        "e2_worker_operator_binding_duplicate_same_pair_preserves_original_finalized_height",
    );
    assert_source_contains("src/e2_worker_evidence.rs", src, "bound_at_height");
}

#[test]
fn worker_already_bound_to_other_operator_is_rejected() {
    let mut chain = crate::Blockchain::new();
    let (_worker_sk, _worker_b64, worker_hex) = test_key(0x37);
    let (_operator_a_sk, _operator_a_b64, operator_a_hex) = test_key(0x38);
    let (_operator_b_sk, _operator_b_b64, operator_b_hex) = test_key(0x39);

    chain
        .apply_e2_worker_operator_binding_from_governance_v1(&worker_hex, &operator_a_hex, 0)
        .expect("first operator binding");
    let err = chain
        .apply_e2_worker_operator_binding_from_governance_v1(&worker_hex, &operator_b_hex, 0)
        .expect_err("active worker cannot be rebound to a different operator");
    assert!(
        err.contains("worker_already_bound"),
        "unexpected error: {err}"
    );

    let binding = chain
        .resolve_e2_worker_operator_binding_finalized_hex_v1(&worker_hex, 0)
        .expect("original binding remains active");
    assert_eq!(binding.operator_wallet_pubkey, operator_a_hex);

    let src = evidence_source();
    assert_source_contains(
        "src/e2_worker_evidence.rs",
        src,
        "e2_worker_operator_binding_allows_one_operator_multiple_workers_v2",
    );
    assert_source_contains("src/e2_worker_evidence.rs", src, "worker_already_bound");
    let chain_src = blockchain_source();
    assert_source_contains(
        "src/blockchain.rs",
        chain_src,
        "self_register_intrablock_same_worker_different_operator_rejected_v1",
    );
    assert_source_contains(
        "src/blockchain.rs",
        chain_src,
        "worker_already_bound_to_different_wallet",
    );
}

#[test]
fn operator_to_n_workers_is_allowed_according_to_v2() {
    let mut chain = crate::Blockchain::new();
    let (_worker_a_sk, _worker_a_b64, worker_a_hex) = test_key(0x3a);
    let (_worker_b_sk, _worker_b_b64, worker_b_hex) = test_key(0x3b);
    let (_operator_sk, _operator_b64, operator_hex) = test_key(0x3c);

    chain
        .apply_e2_worker_operator_binding_from_governance_v1(&worker_a_hex, &operator_hex, 0)
        .expect("first worker binding");
    chain
        .apply_e2_worker_operator_binding_from_governance_v1(&worker_b_hex, &operator_hex, 0)
        .expect("same operator can bind a second worker");

    let rows = chain.canonical_worker_eligibility_finalized_snapshot_v1();
    let worker_count = rows
        .iter()
        .filter(|row| row.operator_wallet_pubkey == operator_hex)
        .count();
    assert_eq!(worker_count, 2, "operator -> N workers must be projected");

    let src = evidence_source();
    assert_source_contains(
        "src/e2_worker_evidence.rs",
        src,
        "e2_worker_operator_binding_allows_one_operator_multiple_workers_v2",
    );
    assert_source_contains(
        "src/e2_worker_evidence.rs",
        src,
        "worker_operator_registry_read_allows_same_operator_for_multiple_workers_v2",
    );
    let chain_src = blockchain_source();
    assert_source_contains(
        "src/blockchain.rs",
        chain_src,
        "self_register_intrablock_same_operator_different_worker_allowed_v2",
    );
}

#[test]
fn evidence_from_unbound_worker_is_rejected() {
    let mut fixture = setup_standard_evidence_fixture(true, false);
    let ev = evidence_for_standard_fixture(&fixture, true, 1);
    let tx = evidence_submit_tx(&fixture.attester_sk, &fixture.attester_pk_b64, ev, 9);
    let before_log_len = fixture.chain.e2_worker_reputation_evidence_log.len();
    let before_ids_len = fixture.chain.e2_worker_reputation_evidence_ids.len();

    let err = fixture
        .chain
        .validate_e2_worker_standard_evidence_tx_v1(&tx)
        .expect_err("unbound worker/operator evidence must be rejected before apply");
    assert!(
        err.contains("e2_worker_evidence_unbound_worker_operator_pair_finalized"),
        "unexpected error: {err}"
    );
    let err = fixture
        .chain
        .apply_e2_worker_standard_evidence_from_compute_tx_v1(&tx, 4)
        .expect_err("unbound worker/operator evidence must not mutate state");
    assert!(
        err.contains("e2_worker_evidence_unbound_worker_operator_pair_finalized"),
        "unexpected apply error: {err}"
    );
    assert_eq!(
        fixture.chain.e2_worker_reputation_evidence_log.len(),
        before_log_len
    );
    assert_eq!(
        fixture.chain.e2_worker_reputation_evidence_ids.len(),
        before_ids_len
    );

    let src = blockchain_source();
    assert_source_contains(
        "src/blockchain.rs",
        src,
        "block5_standard_evidence_unbound_worker_operator_rejected",
    );
}

#[test]
fn evidence_from_bound_worker_is_accepted() {
    let mut fixture = setup_standard_evidence_fixture(true, true);
    let ev = evidence_for_standard_fixture(&fixture, true, 2);
    let tx = evidence_submit_tx(&fixture.attester_sk, &fixture.attester_pk_b64, ev, 10);

    fixture
        .chain
        .validate_e2_worker_standard_evidence_tx_v1(&tx)
        .expect("bound worker/operator evidence must validate");
    let outcome = fixture
        .chain
        .apply_e2_worker_standard_evidence_from_compute_tx_v1(&tx, 4)
        .expect("bound worker/operator evidence apply path must not error")
        .expect("evidence submit tx must produce an outcome");
    assert_eq!(outcome.status, "applied");
    assert!(outcome.applied_delta > 0);
    let key = crate::e2_worker_evidence::e2_worker_history_key_v1(
        &fixture.worker_hex,
        &fixture.operator_hex,
    );
    let history = fixture
        .chain
        .e2_worker_reputation_history_index
        .get(&key)
        .expect("bound evidence must update worker/operator history");
    assert_eq!(history.total_evidence_count, 1);
    assert_eq!(history.source_commitment, "finalized");
}

#[test]
fn non_validator_worker_can_submit_valid_e2_transaction() {
    let fixture = setup_standard_evidence_fixture(true, true);
    let gov = fixture.chain.governance.as_ref().expect("governance");
    assert!(
        !gov.validator_set.entries.iter().any(|v| {
            crate::keyfmt::pk_hex_from_any(&v.pub_key)
                .map(|h| h == fixture.worker_hex)
                .unwrap_or(false)
        }),
        "fixture worker must not be a validator"
    );
    let worker_row = fixture
        .chain
        .canonical_worker_eligibility_finalized_for_worker_v1(&fixture.worker_pk_b64)
        .expect("non-validator worker must still project E2 eligibility after binding");
    assert_eq!(worker_row.worker_node_pubkey, fixture.worker_hex);
    assert_eq!(worker_row.operator_wallet_pubkey, fixture.operator_hex);
    assert!(
        fixture
            .chain
            .compute_order_state_store
            .orders
            .contains_key(&fixture.order_id),
        "valid E2 order/claim/terminal txs from non-validator worker must replay into order state"
    );

    let src = evidence_source();
    assert_source_contains(
        "src/e2_worker_evidence.rs",
        src,
        "e2_worker_operator_binding_accepts_non_validator_worker_identity",
    );
}

#[test]
fn malformed_e2_transaction_is_rejected_without_snapshot_mutation() {
    let mut fixture = setup_standard_evidence_fixture(true, true);
    let ev = evidence_for_standard_fixture(&fixture, true, 3);
    let mut tx = evidence_submit_tx(&fixture.attester_sk, &fixture.attester_pk_b64, ev, 11);
    tx.amount = 1;
    tx.hash = tx.calculate_hash();

    let before_log_len = fixture.chain.e2_worker_reputation_evidence_log.len();
    let before_ids_len = fixture.chain.e2_worker_reputation_evidence_ids.len();
    let before_history_len = fixture.chain.e2_worker_reputation_history_index.len();
    let err = fixture
        .chain
        .validate_e2_worker_standard_evidence_tx_v1(&tx)
        .expect_err("malformed E2 evidence tx amount must be rejected");
    assert!(
        err.contains("e2_worker_evidence_submit_amount_must_be_0"),
        "unexpected validation error: {err}"
    );
    let err = fixture
        .chain
        .apply_e2_worker_standard_evidence_from_compute_tx_v1(&tx, 4)
        .expect_err("malformed E2 evidence tx must fail before snapshot mutation");
    assert!(
        err.contains("e2_worker_evidence_submit_amount_must_be_0"),
        "unexpected apply error: {err}"
    );
    assert_eq!(
        fixture.chain.e2_worker_reputation_evidence_log.len(),
        before_log_len
    );
    assert_eq!(
        fixture.chain.e2_worker_reputation_evidence_ids.len(),
        before_ids_len
    );
    assert_eq!(
        fixture.chain.e2_worker_reputation_history_index.len(),
        before_history_len
    );

    let src = blockchain_source();
    assert_source_contains(
        "src/blockchain.rs",
        src,
        "block5_standard_evidence_bad_signature_rejected",
    );
}

#[test]
fn validator_exit_that_breaks_quorum_is_denied() {
    let mut fixture = setup_operator_l1_transition_fixture(2, 2, 2, 10);
    let proposal = operator_l1_transition_request_proposal(
        "00000000000000000000000000000010",
        &fixture.council_sk,
        &fixture.validator_b_b64,
        &fixture.validator_b_b64,
        20,
        20,
        Some(20),
    );
    apply_operator_l1_governance_proposal_at_finality(
        &mut fixture.gov,
        20,
        20,
        proposal,
        &fixture.council_sk,
    );

    let transition = fixture
        .gov
        .validator_compute_transitions
        .get(&fixture.validator_b_hex)
        .expect("denied transition audit record");
    assert_eq!(
        transition.status,
        crate::governance::ValidatorComputeTransitionStatusV1::Denied
    );
    assert!(transition
        .deny_reasons
        .contains(&"quorum_too_low".to_string()));
    assert!(transition
        .deny_reasons
        .contains(&"finality_quorum_broken".to_string()));
    assert!(fixture
        .gov
        .validator_set
        .entries
        .iter()
        .any(|v| v.pub_key == fixture.validator_b_hex));
}

#[test]
fn validator_exit_pending_record_is_created() {
    let mut fixture = setup_operator_l1_transition_fixture(3, 2, 2, 10);
    let proposal = operator_l1_transition_request_proposal(
        "00000000000000000000000000000011",
        &fixture.council_sk,
        &fixture.validator_b_b64,
        &fixture.validator_b_b64,
        20,
        20,
        Some(0),
    );
    apply_operator_l1_governance_proposal_at_finality(
        &mut fixture.gov,
        20,
        20,
        proposal,
        &fixture.council_sk,
    );

    let pending = fixture
        .gov
        .validator_compute_transitions
        .get(&fixture.validator_b_hex)
        .expect("pending transition record");
    assert_eq!(
        pending.status,
        crate::governance::ValidatorComputeTransitionStatusV1::ExitPending
    );
    assert_eq!(
        pending.requested_at_height, 20,
        "cooldown must be anchored to canonical block height"
    );
    assert!(fixture
        .gov
        .validator_set
        .entries
        .iter()
        .any(|v| v.pub_key == fixture.validator_b_hex));
}

#[test]
fn validator_exit_finalizes_only_after_cooldown_and_recheck() {
    let mut fixture = setup_operator_l1_transition_fixture(3, 2, 2, 10);
    let request = operator_l1_transition_request_proposal(
        "00000000000000000000000000000012",
        &fixture.council_sk,
        &fixture.validator_b_b64,
        &fixture.validator_b_b64,
        20,
        20,
        Some(0),
    );
    apply_operator_l1_governance_proposal_at_finality(
        &mut fixture.gov,
        20,
        20,
        request,
        &fixture.council_sk,
    );

    let early = operator_l1_transition_request_proposal(
        "00000000000000000000000000000013",
        &fixture.council_sk,
        &fixture.validator_b_b64,
        &fixture.validator_b_b64,
        25,
        25,
        Some(0),
    );
    apply_operator_l1_governance_proposal_at_finality(
        &mut fixture.gov,
        25,
        25,
        early,
        &fixture.council_sk,
    );
    let still_pending = fixture
        .gov
        .validator_compute_transitions
        .get(&fixture.validator_b_hex)
        .expect("still pending after early finalization attempt");
    assert_eq!(
        still_pending.status,
        crate::governance::ValidatorComputeTransitionStatusV1::ExitPending
    );
    assert!(still_pending
        .deny_reasons
        .contains(&"cooldown_not_elapsed".to_string()));
    assert!(fixture
        .gov
        .validator_set
        .entries
        .iter()
        .any(|v| v.pub_key == fixture.validator_b_hex));

    let finalization = operator_l1_transition_request_proposal(
        "00000000000000000000000000000014",
        &fixture.council_sk,
        &fixture.validator_b_b64,
        &fixture.validator_b_b64,
        31,
        31,
        Some(0),
    );
    apply_operator_l1_governance_proposal_at_finality(
        &mut fixture.gov,
        31,
        31,
        finalization,
        &fixture.council_sk,
    );
    let finalized = fixture
        .gov
        .validator_compute_transitions
        .get(&fixture.validator_b_hex)
        .expect("finalized transition record");
    assert_eq!(
        finalized.status,
        crate::governance::ValidatorComputeTransitionStatusV1::Finalized
    );
    assert_eq!(finalized.finalized_at_height, Some(31));
    assert!(!fixture
        .gov
        .validator_set
        .entries
        .iter()
        .any(|v| v.pub_key == fixture.validator_b_hex));
}

#[test]
fn cancel_transition_works_only_for_pending_exit() {
    let mut fixture = setup_operator_l1_transition_fixture(3, 2, 2, 10);
    let missing_cancel = operator_l1_transition_cancel_proposal(
        "00000000000000000000000000000015",
        &fixture.council_sk,
        &fixture.validator_b_b64,
        &fixture.validator_b_b64,
        10,
        10,
    );
    apply_operator_l1_governance_proposal_at_finality(
        &mut fixture.gov,
        10,
        10,
        missing_cancel,
        &fixture.council_sk,
    );
    assert!(!fixture
        .gov
        .validator_compute_transitions
        .contains_key(&fixture.validator_b_hex));
    assert_eq!(
        fixture
            .gov
            .proposals
            .get("operator-role-l1-govp-00000000000000000000000000000015")
            .expect("missing cancel proposal record")
            .status,
        crate::governance::ProposalStatus::Rejected
    );

    let request = operator_l1_transition_request_proposal(
        "00000000000000000000000000000016",
        &fixture.council_sk,
        &fixture.validator_b_b64,
        &fixture.validator_b_b64,
        20,
        20,
        Some(20),
    );
    apply_operator_l1_governance_proposal_at_finality(
        &mut fixture.gov,
        20,
        20,
        request,
        &fixture.council_sk,
    );
    assert_eq!(
        fixture
            .gov
            .validator_compute_transitions
            .get(&fixture.validator_b_hex)
            .unwrap()
            .status,
        crate::governance::ValidatorComputeTransitionStatusV1::ExitPending
    );

    let cancel = operator_l1_transition_cancel_proposal(
        "00000000000000000000000000000017",
        &fixture.council_sk,
        &fixture.validator_b_b64,
        &fixture.validator_b_b64,
        21,
        21,
    );
    apply_operator_l1_governance_proposal_at_finality(
        &mut fixture.gov,
        21,
        21,
        cancel,
        &fixture.council_sk,
    );
    assert_eq!(
        fixture
            .gov
            .validator_compute_transitions
            .get(&fixture.validator_b_hex)
            .unwrap()
            .status,
        crate::governance::ValidatorComputeTransitionStatusV1::Cancelled
    );
    assert!(fixture
        .gov
        .validator_set
        .entries
        .iter()
        .any(|v| v.pub_key == fixture.validator_b_hex));

    let cancel_again = operator_l1_transition_cancel_proposal(
        "00000000000000000000000000000018",
        &fixture.council_sk,
        &fixture.validator_b_b64,
        &fixture.validator_b_b64,
        22,
        22,
    );
    apply_operator_l1_governance_proposal_at_finality(
        &mut fixture.gov,
        22,
        22,
        cancel_again,
        &fixture.council_sk,
    );
    assert_eq!(
        fixture
            .gov
            .proposals
            .get("operator-role-l1-govp-00000000000000000000000000000018")
            .expect("second cancel proposal record")
            .status,
        crate::governance::ProposalStatus::Rejected
    );
}

#[test]
fn pending_exit_does_not_avoid_penalty_accounting() {
    let mut fixture = setup_operator_l1_transition_fixture(3, 2, 2, 10);
    let request = operator_l1_transition_request_proposal(
        "00000000000000000000000000000019",
        &fixture.council_sk,
        &fixture.validator_b_b64,
        &fixture.validator_b_b64,
        20,
        20,
        Some(20),
    );
    apply_operator_l1_governance_proposal_at_finality(
        &mut fixture.gov,
        20,
        20,
        request,
        &fixture.council_sk,
    );
    assert_eq!(
        fixture
            .gov
            .validator_compute_transitions
            .get(&fixture.validator_b_hex)
            .unwrap()
            .status,
        crate::governance::ValidatorComputeTransitionStatusV1::ExitPending
    );
    assert!(fixture
        .gov
        .validator_set
        .entries
        .iter()
        .any(|v| v.pub_key == fixture.validator_b_hex));

    let rep = fixture
        .gov
        .validator_reputation
        .entry(fixture.validator_b_hex.clone())
        .or_default();
    rep.downtime_missed_turns_total = rep.downtime_missed_turns_total.saturating_add(1);
    rep.downtime_consecutive_missed_turns = rep.downtime_consecutive_missed_turns.saturating_add(1);
    rep.misbehavior_points = rep.misbehavior_points.saturating_add(1);

    let rep_after = fixture
        .gov
        .validator_reputation
        .get(&fixture.validator_b_hex)
        .unwrap();
    assert_eq!(rep_after.downtime_missed_turns_total, 1);
    assert_eq!(rep_after.downtime_consecutive_missed_turns, 1);
    assert_eq!(rep_after.misbehavior_points, 1);
    assert!(
        crate::governance::validator_quality_score_for_operator_role_model_v2(rep_after, 21) < 1000,
        "pending exit validator must stay visible to downtime/penalty accounting until finalization"
    );

    let src = blockchain_source();
    assert_source_contains(
        "src/blockchain.rs",
        src,
        "validator_compute_transition_exit_pending_remains_visible_to_downtime_policy",
    );
    assert_source_contains("src/blockchain.rs", src, "apply_downtime_policy_plan");
}

#[test]
fn validator_set_update_respects_min_active_validators() {
    let mut fixture = setup_operator_l1_transition_fixture(3, 3, 2, 10);
    let proposal = operator_l1_transition_request_proposal(
        "00000000000000000000000000000020",
        &fixture.council_sk,
        &fixture.validator_b_b64,
        &fixture.validator_b_b64,
        20,
        20,
        Some(20),
    );
    apply_operator_l1_governance_proposal_at_finality(
        &mut fixture.gov,
        20,
        20,
        proposal,
        &fixture.council_sk,
    );

    let transition = fixture
        .gov
        .validator_compute_transitions
        .get(&fixture.validator_b_hex)
        .expect("min-active denied transition record");
    assert_eq!(
        transition.status,
        crate::governance::ValidatorComputeTransitionStatusV1::Denied
    );
    assert!(transition
        .deny_reasons
        .contains(&"quorum_too_low".to_string()));
    assert!(fixture
        .gov
        .validator_set
        .entries
        .iter()
        .any(|v| v.pub_key == fixture.validator_b_hex));
    assert_eq!(
        fixture
            .gov
            .params
            .validator_compute_transition_min_active_validators,
        3
    );
}

#[test]
fn operator_role_model_l1_test_suite_maps_all_required_cases() {
    let this_file = include_str!("operator_role_model_l1_tests.rs");
    for required in [
        "self_registration_requires_operator_wallet_as_tx_sender",
        "worker_key_and_operator_wallet_are_distinct",
        "binding_duplicate_same_pair_is_idempotent",
        "worker_already_bound_to_other_operator_is_rejected",
        "operator_to_n_workers_is_allowed_according_to_v2",
        "evidence_from_unbound_worker_is_rejected",
        "evidence_from_bound_worker_is_accepted",
        "non_validator_worker_can_submit_valid_e2_transaction",
        "malformed_e2_transaction_is_rejected_without_snapshot_mutation",
        "validator_exit_that_breaks_quorum_is_denied",
        "validator_exit_pending_record_is_created",
        "validator_exit_finalizes_only_after_cooldown_and_recheck",
        "cancel_transition_works_only_for_pending_exit",
        "pending_exit_does_not_avoid_penalty_accounting",
        "validator_set_update_respects_min_active_validators",
    ] {
        assert_source_contains("src/operator_role_model_l1_tests.rs", this_file, required);
    }
}
