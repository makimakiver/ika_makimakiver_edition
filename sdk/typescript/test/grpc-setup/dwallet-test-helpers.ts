// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { SuiGrpcClient } from '@mysten/sui/grpc';
import { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';

import {
	DKGRequestInput,
	ImportDWalletVerificationRequestInput,
	prepareDKGAsync,
	prepareDKGSecondRoundAsync,
	sessionIdentifierDigest,
} from '../../src/client/cryptography.js';
import {
	Curve,
	DWallet,
	EncryptedUserSecretKeyShare,
	EncryptionKey,
	Hash,
	ImportedKeyDWallet,
	ImportedSharedDWallet,
	PartialUserSignature,
	Presign,
	SharedDWallet,
	SignatureAlgorithm,
	ZeroTrustDWallet,
} from '../../src/client/types.js';
import type { UserShareEncryptionKeys } from '../../src/client/user-share-encryption-keys.js';
import * as CoordinatorInnerModule from '../../src/generated/ika_dwallet_2pc_mpc/coordinator_inner.js';
import { UserSecretKeyShareEventType } from '../../src/generated/ika_dwallet_2pc_mpc/coordinator_inner.js';
import * as SessionsManagerModule from '../../src/generated/ika_dwallet_2pc_mpc/sessions_manager.js';
import { grpcPrepareDKGAsync, IkaGrpcClient } from '../../src/index.js';
import {
	createEmptyTestIkaToken,
	createTestIkaTransaction,
	delay,
	destroyEmptyTestIkaToken,
	executeTestTransaction,
	generateTestKeypair,
	requestTestFaucetFunds,
	retryUntil,
} from './test-utils.js';

/**
 * Complete DWallet creation process for testing.
 * This combines all the steps needed to create an active DWallet with an encrypted user share.
 */
export async function createCompleteDWallet(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	testName: string,
	registerEncryptionKey: boolean = true,
): Promise<{
	dWallet: DWallet;
	encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
	userShareEncryptionKeys: UserShareEncryptionKeys;
	signerAddress: string;
}> {
	// Generate deterministic keypair for this test
	const { userShareEncryptionKeys, signerPublicKey, signerAddress } =
		await generateTestKeypair(testName);

	// Request faucet funds for the test address
	await requestTestFaucetFunds(signerAddress);

	// Step 1: Request DKG first round
	const { dwalletID, sessionIdentifierPreimage } = await requestTestDKGFirstRound(
		ikaClient,
		suiClient,
		signerAddress,
		testName,
	);

	await delay(5); // Wait for 5 seconds to ensure the DWallet is created

	// Step 2: Register encryption key
	if (registerEncryptionKey) {
		await registerTestEncryptionKey(ikaClient, suiClient, userShareEncryptionKeys, testName);
	}

	// Step 3: Wait for DWallet to be in AwaitingUserDKGVerificationInitiation state
	const dWallet = await retryUntil(
		() => ikaClient.getDWalletInParticularState(dwalletID, 'AwaitingUserDKGVerificationInitiation'),
		(wallet) => wallet !== null,
		30,
		2000,
	);

	// Step 4: Prepare DKG second round
	const dkgSecondRoundRequestInput = await prepareDKGSecondRoundAsync(
		ikaClient,
		dWallet,
		userShareEncryptionKeys,
	);

	// Step 5: Request DKG second round
	const secondRoundMoveResponse = await requestTestDkgSecondRound(
		ikaClient,
		suiClient,
		dWallet,
		dkgSecondRoundRequestInput,
		userShareEncryptionKeys,
		testName,
	);

	// Step 6: Wait for DWallet to be AwaitingKeyHolderSignature
	const awaitingKeyHolderSignatureDWallet = await retryUntil(
		() => ikaClient.getDWalletInParticularState(dwalletID, 'AwaitingKeyHolderSignature'),
		(wallet) => wallet !== null,
		30,
		2000,
	);

	// Step 7: Accept encrypted user share
	// Type assertion: DKG flow only creates ZeroTrust DWallets
	await acceptTestEncryptedUserShare(
		ikaClient,
		suiClient,
		awaitingKeyHolderSignatureDWallet as ZeroTrustDWallet,
		dkgSecondRoundRequestInput.userPublicOutput,
		secondRoundMoveResponse,
		userShareEncryptionKeys,
		testName,
	);

	// Step 8: Wait for DWallet to be Active
	const activeDWallet = await retryUntil(
		() => ikaClient.getDWalletInParticularState(dwalletID, 'Active'),
		(wallet) => wallet !== null,
		30,
		2000,
	);

	// Step 9: Get the encrypted user secret key share
	const encryptedUserSecretKeyShare = await retryUntil(
		() =>
			ikaClient.getEncryptedUserSecretKeyShare(
				secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id,
			),
		(share) => share !== null,
		30,
		1000,
	);

	return {
		dWallet: activeDWallet,
		encryptedUserSecretKeyShare,
		userShareEncryptionKeys,
		signerAddress,
	};
}

/**
 * Complete DWallet creation process for testing.
 * This combines all the steps needed to create an active DWallet with an encrypted user share.
 */
export async function createCompleteDWalletV2(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	testName: string,
	registerEncryptionKey: boolean = true,
): Promise<{
	dWallet: DWallet;
	encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
	userShareEncryptionKeys: UserShareEncryptionKeys;
	signerAddress: string;
}> {
	// Generate deterministic keypair for this test
	const { userShareEncryptionKeys, signerPublicKey, signerAddress } =
		await generateTestKeypair(testName);

	// Request faucet funds for the test address
	await requestTestFaucetFunds(signerAddress);

	const createSessionIDTx = new Transaction();
	const createSessionIDIkaTx = createTestIkaTransaction(
		ikaClient,
		createSessionIDTx,
		userShareEncryptionKeys,
	);
	const sessionIdentifier = createSessionIDIkaTx.createSessionIdentifier();
	createSessionIDTx.transferObjects([sessionIdentifier], signerAddress);
	// Sleep for a bit to free the signer keypair gas object
	await delay(5);
	const registerSessionIDResult = await executeTestTransaction(
		suiClient,
		createSessionIDTx,
		testName,
	);
	const waitForRegisterResult = await suiClient.waitForTransaction({
		digest: registerSessionIDResult.Transaction?.digest as string,
		include: { events: true },
	});
	const registeredSessionIDEvent = waitForRegisterResult.Transaction?.events?.find((event) =>
		event.eventType.includes('UserSessionIdentifierRegisteredEvent'),
	);
	if (!registeredSessionIDEvent?.bcs)
		throw new Error('UserSessionIdentifierRegisteredEvent not found');
	let parsedEvent = SessionsManagerModule.UserSessionIdentifierRegisteredEvent.parse(
		registeredSessionIDEvent.bcs,
	);

	await delay(5); // Wait for 5 seconds to ensure the DWallet is created

	// Step 2: Register encryption key
	if (registerEncryptionKey) {
		await registerTestEncryptionKey(ikaClient, suiClient, userShareEncryptionKeys, testName);
	}

	// Step 4: Prepare network DKG input
	const dkgSecondRoundRequestInput = await grpcPrepareDKGAsync(
		ikaClient,
		userShareEncryptionKeys,
		sessionIdentifierDigest(Uint8Array.from(parsedEvent.session_identifier_preimage)),
	);

	// Step 5: Request DKG second round
	const decentralizedRoundMoveResponse = await requestTestDkg(
		ikaClient,
		suiClient,
		dkgSecondRoundRequestInput,
		userShareEncryptionKeys,
		testName,
		parsedEvent.session_object_id,
		(await ikaClient.getConfiguredNetworkEncryptionKey()).id,
		Curve.SECP256K1,
		signerAddress,
	);

	// Step 6: Wait for DWallet to be AwaitingKeyHolderSignature
	const dwalletID = decentralizedRoundMoveResponse.event_data.dwallet_id;
	const awaitingKeyHolderSignatureDWallet = await retryUntil(
		() => ikaClient.getDWalletInParticularState(dwalletID, 'AwaitingKeyHolderSignature'),
		(wallet) => wallet !== null,
		30,
		2000,
	);
	console.log(
		'DWallet Output (base64):',
		Buffer.from(
			awaitingKeyHolderSignatureDWallet.state.AwaitingKeyHolderSignature.public_output,
		).toString('base64'),
	);

	// Step 7: Accept encrypted user share
	// Type assertion: DKG flow only creates ZeroTrust DWallets
	await acceptTestEncryptedUserShare(
		ikaClient,
		suiClient,
		awaitingKeyHolderSignatureDWallet as ZeroTrustDWallet,
		dkgSecondRoundRequestInput.userPublicOutput,
		decentralizedRoundMoveResponse,
		userShareEncryptionKeys,
		testName,
	);

	// Step 8: Wait for DWallet to be Active
	const activeDWallet = await retryUntil(
		() => ikaClient.getDWalletInParticularState(dwalletID, 'Active'),
		(wallet) => wallet !== null,
		30,
		2000,
	);

	// Step 9: Get the encrypted user secret key share
	const encryptedUserSecretKeyShare = await retryUntil(
		() =>
			ikaClient.getEncryptedUserSecretKeyShare(
				decentralizedRoundMoveResponse.event_data.user_secret_key_share.Encrypted
					.encrypted_user_secret_key_share_id,
			),
		(share) => share !== null,
		30,
		1000,
	);

	return {
		dWallet: activeDWallet,
		encryptedUserSecretKeyShare,
		userShareEncryptionKeys,
		signerAddress,
	};
}

/**
 * Request DKG first round for testinginitial_shared_version
 */
export async function requestTestDKGFirstRound(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	signerAddress: string,
	testName: string,
): Promise<{
	dwalletID: string;
	sessionIdentifierPreimage: Uint8Array;
}> {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction);

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	const dwalletCap = await ikaTransaction.requestDWalletDKGFirstRoundAsync({
		curve: Curve.SECP256K1,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	transaction.transferObjects([dwalletCap], signerAddress);

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTestTransaction(suiClient, transaction, testName);
	const waitForTransactionResult = await suiClient.waitForTransaction({
		digest: result.Transaction?.digest as string,
		include: { events: true },
	});

	const startDKGFirstRoundEvent = waitForTransactionResult.Transaction?.events?.find(
		(event) =>
			event.eventType.includes('DWalletDKGFirstRoundRequestEvent') &&
			event.eventType.includes('DWalletSessionEvent'),
	);

	if (!startDKGFirstRoundEvent?.bcs) {
		throw new Error(
			'Failed to extract DWallet ID or session identifier from DKG first round request',
		);
	}

	const parsedFirstRoundEvent = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.DWalletDKGFirstRoundRequestEvent,
	).parse(startDKGFirstRoundEvent.bcs);

	const dwalletID = parsedFirstRoundEvent.event_data.dwallet_id;
	const sessionIdentifierPreimage = parsedFirstRoundEvent.session_identifier_preimage;

	if (!dwalletID || !sessionIdentifierPreimage) {
		throw new Error(
			'Failed to extract DWallet ID or session identifier from DKG first round request',
		);
	}

	return {
		dwalletID: dwalletID as string,
		sessionIdentifierPreimage: new Uint8Array(sessionIdentifierPreimage as number[]),
	};
}

/**
 * Register encryption key for testing
 */
export async function registerTestEncryptionKey(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	await ikaTransaction.registerEncryptionKey({
		curve: Curve.SECP256K1,
	});

	const result = await executeTestTransaction(suiClient, transaction, testName);
	const waitForTransactionResult = await suiClient.waitForTransaction({
		digest: result.Transaction?.digest as string,
		include: { events: true },
	});

	const createdEncryptionKeyEvent = waitForTransactionResult.Transaction?.events?.find((event) =>
		event.eventType.includes('CreatedEncryptionKeyEvent'),
	);

	if (!createdEncryptionKeyEvent?.bcs) {
		throw new Error('Failed to find CreatedEncryptionKeyEvent');
	}

	return CoordinatorInnerModule.CreatedEncryptionKeyEvent.parse(createdEncryptionKeyEvent.bcs);
}

/**
 * Request DKG second round for testing
 */
export async function requestTestDkgSecondRound(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	dWallet: DWallet,
	dkgSecondRoundRequestInput: DKGRequestInput,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	ikaTransaction.requestDWalletDKGSecondRound({
		dWalletCap: dWallet.dwallet_cap_id,
		dkgSecondRoundRequestInput,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTestTransaction(suiClient, transaction, testName);
	const waitForTransactionResult = await suiClient.waitForTransaction({
		digest: result.Transaction?.digest as string,
		include: { events: true },
	});

	const dkgSecondRoundRequestEvent = waitForTransactionResult.Transaction?.events?.find(
		(event) =>
			event.eventType.includes('DWalletDKGSecondRoundRequestEvent') &&
			event.eventType.includes('DWalletSessionEvent'),
	);

	if (!dkgSecondRoundRequestEvent?.bcs) {
		throw new Error('Failed to find DWalletDKGSecondRoundRequestEvent');
	}

	return SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.DWalletDKGSecondRoundRequestEvent,
	).parse(dkgSecondRoundRequestEvent.bcs);
}

function numberToCurve(curve: number): Curve {
	switch (curve) {
		case 0:
			return Curve.SECP256K1;
		case 1:
			return Curve.RISTRETTO;
		case 2:
			return Curve.ED25519;
		case 3:
			return Curve.SECP256R1;
	}
}

/**
 * Request DKG second round for testing
 */
export async function requestTestDkg(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	dkgSecondRoundRequestInput: DKGRequestInput,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	testName: string,
	sessionIdentifierObjID: string,
	dwalletNetworkEncryptionKeyId: string,
	curve: number,
	signerAddress: string,
) {
	const transaction = new Transaction();
	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);
	const [dWalletCap] = await ikaTransaction.requestDWalletDKG({
		dkgRequestInput: dkgSecondRoundRequestInput,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
		sessionIdentifierObjID,
		dwalletNetworkEncryptionKeyId,
		curve: numberToCurve(curve),
	});
	transaction.transferObjects([dWalletCap], signerAddress);

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTestTransaction(suiClient, transaction, testName);
	const waitForTransactionResult = await suiClient.waitForTransaction({
		digest: result.Transaction?.digest as string,
		include: { events: true },
	});

	const dkgRequestEvent = waitForTransactionResult.Transaction?.events?.find(
		(event) =>
			event.eventType.includes('DWalletDKGRequestEvent') &&
			event.eventType.includes('DWalletSessionEvent'),
	);

	if (!dkgRequestEvent?.bcs) {
		throw new Error('Failed to find DWalletDKGRequestEvent');
	}

	return SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.DWalletDKGRequestEvent,
	).parse(dkgRequestEvent.bcs);
}

/**
 * Request DKG second round for testing
 */
export async function requestTestDkgWithPublicUserShare(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	testName: string,
	sessionIdentifier: TransactionObjectArgument,
	dwalletNetworkEncryptionKeyId: string,
	curve: number,
	signerAddress: string,
	publicKeyShareAndProof: Uint8Array,
	publicUserSecretKeyShare: Uint8Array,
	userPublicOutput: Uint8Array,
) {
	const transaction = new Transaction();
	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);
	const [dWalletCap] = await ikaTransaction.requestDWalletDKGWithPublicUserShare({
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
		sessionIdentifier,
		dwalletNetworkEncryptionKeyId,
		curve: numberToCurve(curve),
		publicKeyShareAndProof,
		publicUserSecretKeyShare,
		userPublicOutput,
	});
	transaction.transferObjects([dWalletCap], signerAddress);

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTestTransaction(suiClient, transaction, testName);
	const waitForTransactionResult = await suiClient.waitForTransaction({
		digest: result.Transaction?.digest as string,
		include: { events: true },
	});

	const dkgRequestEvent = waitForTransactionResult.Transaction?.events?.find(
		(event) =>
			event.eventType.includes('DWalletDKGRequestEvent') &&
			event.eventType.includes('DWalletSessionEvent'),
	);

	if (!dkgRequestEvent?.bcs) {
		throw new Error('Failed to find DWalletDKGRequestEvent');
	}

	return SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.DWalletDKGRequestEvent,
	).parse(dkgRequestEvent.bcs);
}

interface EncryptedShare {
	Encrypted: {
		encrypted_user_secret_key_share_id: string;
	};
}

interface PublicShare {
	Public: {};
}

/**
 * Accept encrypted user share for testing
 */
export async function acceptTestEncryptedUserShare(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	dWallet: ZeroTrustDWallet | ImportedKeyDWallet,
	userPublicOutput: Uint8Array,
	secondRoundMoveResponse: {
		event_data: {
			user_secret_key_share: EncryptedShare;
		};
	},
	userShareEncryptionKeys: UserShareEncryptionKeys,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	await ikaTransaction.acceptEncryptedUserShare({
		dWallet,
		userPublicOutput,
		encryptedUserSecretKeyShareId:
			secondRoundMoveResponse.event_data.user_secret_key_share.Encrypted
				.encrypted_user_secret_key_share_id,
	});

	await executeTestTransaction(suiClient, transaction, testName);
}

/**
 * Accept encrypted user share for transferred DWallet for testing
 */
export async function acceptTestEncryptedUserShareForTransferredDWallet(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	dWallet: ZeroTrustDWallet | ImportedKeyDWallet,
	destinationUserShareEncryptionKeys: UserShareEncryptionKeys,
	sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	sourceEncryptionKey: EncryptionKey,
	destinationEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(
		ikaClient,
		transaction,
		destinationUserShareEncryptionKeys,
	);

	await ikaTransaction.acceptEncryptedUserShare({
		dWallet,
		sourceEncryptedUserSecretKeyShare,
		sourceEncryptionKey,
		destinationEncryptedUserSecretKeyShare,
	});

	await executeTestTransaction(suiClient, transaction, testName);
}

/**
 * Make DWallet user secret key shares public for testing
 */
export async function makeTestDWalletUserSecretKeySharesPublic(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	dWallet: ZeroTrustDWallet | ImportedKeyDWallet,
	secretShare: Uint8Array,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction);

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	ikaTransaction.makeDWalletUserSecretKeySharesPublic({
		dWallet,
		secretShare,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTestTransaction(suiClient, transaction, testName);
}

/**
 * Make Imported Key DWallet user secret key shares public for testing
 */
export async function makeTestImportedKeyDWalletUserSecretKeySharesPublic(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	dWallet: ZeroTrustDWallet | ImportedKeyDWallet,
	secretShare: Uint8Array,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction);

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	ikaTransaction.makeDWalletUserSecretKeySharesPublic({
		dWallet,
		secretShare,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTestTransaction(suiClient, transaction, testName);
}

/**
 * Presign for testing
 */
export async function testPresign(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	dWallet: DWallet,
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	signerAddress: string,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction);

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	let unverifiedPresignCap;

	if (
		dWallet.is_imported_key_dwallet &&
		(signatureAlgorithm === SignatureAlgorithm.ECDSASecp256k1 ||
			signatureAlgorithm === SignatureAlgorithm.ECDSASecp256r1)
	) {
		unverifiedPresignCap = ikaTransaction.requestPresign({
			dWallet,
			signatureAlgorithm,
			ikaCoin: emptyIKACoin,
			suiCoin: transaction.gas,
		});
	} else {
		unverifiedPresignCap = ikaTransaction.requestGlobalPresign({
			curve,
			dwalletNetworkEncryptionKeyId: dWallet.dwallet_network_encryption_key_id,
			signatureAlgorithm,
			ikaCoin: emptyIKACoin,
			suiCoin: transaction.gas,
		});
	}

	transaction.transferObjects([unverifiedPresignCap], signerAddress);

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTestTransaction(suiClient, transaction, testName);
	const waitForTransactionResult = await suiClient.waitForTransaction({
		digest: result.Transaction?.digest as string,
		include: { events: true },
	});

	const presignRequestEvent = waitForTransactionResult.Transaction?.events?.find(
		(event) =>
			event.eventType.includes('PresignRequestEvent') &&
			event.eventType.includes('DWalletSessionEvent'),
	);

	if (!presignRequestEvent?.bcs) {
		throw new Error('Failed to find PresignRequestEvent');
	}

	return SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.PresignRequestEvent,
	).parse(presignRequestEvent.bcs);
}

/**
 * Sign for testing
 */
export async function testSign(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	dWallet: ZeroTrustDWallet | ImportedKeyDWallet,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	presign: Presign,
	encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const messageApproval = ikaTransaction.approveMessage({
		dWalletCap: dWallet.dwallet_cap_id,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const verifiedPresignCap = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	// Use appropriate signing method based on DWallet type
	if (dWallet.kind === 'imported-key') {
		const importedKeyMessageApproval = ikaTransaction.approveImportedKeyMessage({
			dWalletCap: dWallet.dwallet_cap_id,
			signatureAlgorithm,
			hashScheme,
			message,
		});

		await ikaTransaction.requestSignWithImportedKey({
			dWallet,
			importedKeyMessageApproval,
			verifiedPresignCap,
			hashScheme,
			presign,
			encryptedUserSecretKeyShare,
			message,
			ikaCoin: emptyIKACoin,
			suiCoin: transaction.gas,
		});
	} else {
		await ikaTransaction.requestSign({
			dWallet,
			messageApproval,
			verifiedPresignCap,
			hashScheme,
			presign,
			encryptedUserSecretKeyShare,
			message,
			ikaCoin: emptyIKACoin,
			suiCoin: transaction.gas,
		});
	}

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTestTransaction(suiClient, transaction, testName);
}

/**
 * Sign with public user share for testing
 */
export async function testSignPublicUserShare(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	dWallet: SharedDWallet | ImportedSharedDWallet,
	presign: Presign,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction);

	const messageApproval = ikaTransaction.approveMessage({
		dWalletCap: dWallet.dwallet_cap_id,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const verifiedPresignCap = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	// Use appropriate signing method based on DWallet type
	if (dWallet.kind === 'imported-key-shared') {
		const importedKeyMessageApproval = ikaTransaction.approveImportedKeyMessage({
			dWalletCap: dWallet.dwallet_cap_id,
			signatureAlgorithm,
			hashScheme,
			message,
		});

		await ikaTransaction.requestSignWithImportedKey({
			dWallet,
			importedKeyMessageApproval,
			verifiedPresignCap,
			presign,
			message,
			hashScheme,
			ikaCoin: emptyIKACoin,
			suiCoin: transaction.gas,
		});
	} else {
		await ikaTransaction.requestSign({
			dWallet,
			messageApproval,
			verifiedPresignCap,
			presign,
			message,
			hashScheme,
			ikaCoin: emptyIKACoin,
			suiCoin: transaction.gas,
		});
	}

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTestTransaction(suiClient, transaction, testName);
}

/**
 * Request future sign for testing
 */
export async function requestTestFutureSign(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	dWallet: ZeroTrustDWallet | ImportedKeyDWallet,
	presign: Presign,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	message: Uint8Array,
	hashScheme: Hash,
	signerAddress: string,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const verifiedPresignCap = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	let unverifiedPartialUserSignatureCap2: TransactionObjectArgument;

	// Use appropriate future signing method based on DWallet type
	if (dWallet.kind === 'imported-key') {
		const unverifiedPartialUserSignatureCap = await ikaTransaction.requestFutureSignWithImportedKey(
			{
				dWallet,
				presign,
				verifiedPresignCap,
				encryptedUserSecretKeyShare,
				message,
				hashScheme,
				ikaCoin: emptyIKACoin,
				suiCoin: transaction.gas,
			},
		);

		unverifiedPartialUserSignatureCap2 = unverifiedPartialUserSignatureCap;
	} else {
		const unverifiedPartialUserSignatureCap = await ikaTransaction.requestFutureSign({
			dWallet,
			presign,
			verifiedPresignCap,
			encryptedUserSecretKeyShare,
			message,
			hashScheme,
			ikaCoin: emptyIKACoin,
			suiCoin: transaction.gas,
		});

		unverifiedPartialUserSignatureCap2 = unverifiedPartialUserSignatureCap;
	}

	transaction.transferObjects([unverifiedPartialUserSignatureCap2], signerAddress);

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTestTransaction(suiClient, transaction, testName);
	const waitForTransactionResult = await suiClient.waitForTransaction({
		digest: result.Transaction?.digest as string,
		include: { events: true },
	});

	const futureSignRequestEvent = waitForTransactionResult.Transaction?.events?.find(
		(event) =>
			event.eventType.includes('FutureSignRequestEvent') &&
			event.eventType.includes('DWalletSessionEvent'),
	);

	if (!futureSignRequestEvent?.bcs) {
		throw new Error('Failed to find FutureSignRequestEvent');
	}

	return SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.FutureSignRequestEvent,
	).parse(futureSignRequestEvent.bcs);
}

/**
 * Future sign for testing
 */
export async function testFutureSign(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	dWallet: DWallet,
	partialUserSignature: PartialUserSignature,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const messageApproval = ikaTransaction.approveMessage({
		dWalletCap: dWallet.dwallet_cap_id,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	ikaTransaction.futureSign({
		messageApproval,
		partialUserSignatureCap: partialUserSignature.cap_id,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTestTransaction(suiClient, transaction, testName);
}

/**
 * Request Imported Key DWallet verification for testing
 */
export async function requestTestImportedKeyDWalletVerification(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	importDWalletVerificationRequestInput: ImportDWalletVerificationRequestInput,
	curve: Curve,
	signerPublicKey: Uint8Array,
	sessionIdentifier: string,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	receiver: string,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	const importedKeyDWalletCap = await ikaTransaction.requestImportedKeyDWalletVerification({
		importDWalletVerificationRequestInput,
		curve,
		signerPublicKey,
		sessionIdentifier,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	transaction.transferObjects([importedKeyDWalletCap], receiver);

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTestTransaction(suiClient, transaction, testName);
	const waitForTransactionResult = await suiClient.waitForTransaction({
		digest: result.Transaction?.digest as string,
		include: { events: true },
	});

	const importedKeyDWalletVerificationRequestEvent =
		waitForTransactionResult.Transaction?.events?.find((event) =>
			event.eventType.includes('DWalletImportedKeyVerificationRequestEvent'),
		);

	if (!importedKeyDWalletVerificationRequestEvent?.bcs) {
		throw new Error('Failed to find DWalletImportedKeyVerificationRequestEvent');
	}

	return SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.DWalletImportedKeyVerificationRequestEvent,
	).parse(importedKeyDWalletVerificationRequestEvent.bcs);
}

/**
 * Sign with Imported Key DWallet for testing
 */
export async function testSignWithImportedKeyDWallet(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	dWallet: ImportedKeyDWallet,
	presign: Presign,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const importedKeyMessageApproval = ikaTransaction.approveImportedKeyMessage({
		dWalletCap: dWallet.dwallet_cap_id,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const verifiedPresignCap = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.requestSignWithImportedKey({
		dWallet,
		encryptedUserSecretKeyShare,
		presign,
		hashScheme,
		message,
		importedKeyMessageApproval,
		verifiedPresignCap,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTestTransaction(suiClient, transaction, testName);
}

/**
 * Sign with Imported Key DWallet public for testing
 */
export async function testSignWithImportedKeyDWalletPublic(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	dWallet: ImportedSharedDWallet,
	presign: Presign,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction);

	const importedKeyMessageApproval = ikaTransaction.approveImportedKeyMessage({
		dWalletCap: dWallet.dwallet_cap_id,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const verifiedPresignCap = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.requestSignWithImportedKey({
		dWallet,
		presign,
		hashScheme,
		message,
		importedKeyMessageApproval,
		verifiedPresignCap,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTestTransaction(suiClient, transaction, testName);
}

/**
 * Transfer encrypted user share for testing
 */
export async function testTransferEncryptedUserShare(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	dWallet: ZeroTrustDWallet | ImportedKeyDWallet,
	destinationEncryptionKeyAddress: string,
	sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.requestReEncryptUserShareFor({
		dWallet,
		destinationEncryptionKeyAddress,
		sourceEncryptedUserSecretKeyShare,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTestTransaction(suiClient, transaction, testName);
	const waitForTransactionResult = await suiClient.waitForTransaction({
		digest: result.Transaction?.digest as string,
		include: { events: true },
	});

	const transferUserShareEvent = waitForTransactionResult.Transaction?.events?.find((event) =>
		event.eventType.includes('EncryptedShareVerificationRequestEvent'),
	);

	if (!transferUserShareEvent?.bcs) {
		throw new Error('Failed to find EncryptedShareVerificationRequestEvent');
	}

	return SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.EncryptedShareVerificationRequestEvent,
	).parse(transferUserShareEvent.bcs);
}

/**
 * Create session identifier for testing
 */
export async function createTestSessionIdentifier(
	ikaClient: IkaGrpcClient,
	suiClient: SuiGrpcClient,
	receiver: string,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction);

	const sessionIdentifier = ikaTransaction.createSessionIdentifier();
	transaction.transferObjects([sessionIdentifier], receiver);

	const result = await executeTestTransaction(suiClient, transaction, testName);
	const waitForTransactionResult = await suiClient.waitForTransaction({
		digest: result.Transaction?.digest as string,
		include: { events: true },
	});

	const sessionIdentifierRegisteredEvent = waitForTransactionResult.Transaction?.events?.find(
		(event) => event.eventType.includes('SessionIdentifierRegisteredEvent'),
	);

	if (!sessionIdentifierRegisteredEvent?.bcs) {
		throw new Error('Failed to find SessionIdentifierRegisteredEvent');
	}

	const sessionIdentifierRegisteredEventParsed =
		SessionsManagerModule.UserSessionIdentifierRegisteredEvent.parse(
			sessionIdentifierRegisteredEvent.bcs,
		);

	return {
		sessionIdentifier: sessionIdentifierRegisteredEventParsed.session_object_id,
		sessionIdentifierPreimage: new Uint8Array(
			sessionIdentifierRegisteredEventParsed.session_identifier_preimage,
		),
	};
}
