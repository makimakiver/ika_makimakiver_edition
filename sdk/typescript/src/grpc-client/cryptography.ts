// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { bcs } from '@mysten/sui/bcs';

import type {
	DKGRequestInput,
	ImportDWalletVerificationRequestInput,
} from '../client/cryptography.js';
import { encryptSecretShare, prepareDKG, sessionIdentifierDigest } from '../client/cryptography.js';
import { fromCurveToNumber } from '../client/hash-signature-validation.js';
import type { Curve, DWallet } from '../client/types.js';
import type { UserShareEncryptionKeys } from '../client/user-share-encryption-keys.js';
import { create_imported_dwallet_centralized_step as create_imported_dwallet_user_output } from '../client/wasm-loader.js';
import type { IkaGrpcClient } from './ika-client.js';

/**
 * @deprecated Use prepareDKGAsync instead
 *
 * @param ikaClient - The IkaClient instance to fetch network parameters from
 * @param dWallet - The DWallet object containing first round output
 * @param userShareEncryptionKeys - The user's encryption keys for securing the user's share
 * @returns Promise resolving to complete prepared data for the second DKG round
 * @throws {Error} If the first round output is not available or network parameters cannot be fetched
 *
 * SECURITY WARNING: *secret key share must be kept private!* never send it to anyone, or store it anywhere unencrypted.
 */
export async function grpcPrepareDKGSecondRoundAsync(
	_ikaClient: IkaGrpcClient,
	_dWallet: DWallet,
	_userShareEncryptionKeys: UserShareEncryptionKeys,
): Promise<DKGRequestInput> {
	throw new Error('prepareDKGSecondRoundAsync is deprecated. Use prepareDKGAsync instead');
}

/**
 * Prepare all cryptographic data needed for DKG (async version that fetches protocol parameters).
 *
 * @param ikaClient - The IkaClient instance to fetch network parameters from
 * @param curve - The curve to use for key generation
 * @param userShareEncryptionKeys - The user's encryption keys for securing the user's share
 * @param bytesToHash - The bytes to hash for session identifier generation
 * @param senderAddress - The sender address for session identifier generation
 * @returns Promise resolving to complete prepared data for DKG including user message, public output, encrypted share, and secret key share
 * @throws {Error} If network parameters cannot be fetched
 *
 * SECURITY WARNING: *secret key share must be kept private!* never send it to anyone, or store it anywhere unencrypted.
 */
export async function grpcPrepareDKGAsync(
	ikaClient: IkaGrpcClient,
	curve: Curve,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	bytesToHash: Uint8Array,
	senderAddress: string,
): Promise<DKGRequestInput> {
	const protocolPublicParameters = await ikaClient.getProtocolPublicParameters(undefined, curve);

	return prepareDKG(
		protocolPublicParameters,
		curve,
		userShareEncryptionKeys.encryptionKey,
		bytesToHash,
		senderAddress,
	);
}

/**
 * Prepare verification data for importing an existing cryptographic key as a DWallet.
 * This function creates all necessary proofs and encrypted data for the import process.
 *
 * @param ikaClient - The IkaClient instance to fetch network parameters from
 * @param curve - The curve to use for key generation
 * @param bytesToHash - The bytes to hash for session identifier generation
 * @param senderAddress - The sender address for session identifier generation
 * @param userShareEncryptionKeys - The user's encryption keys for securing the imported share
 * @param privateKey - The existing private key to import as a DWallet
 * @returns Promise resolving to complete verification data for the import process including user public output, message, and encrypted share
 * @throws {Error} If network parameters cannot be fetched or key import preparation fails
 */
export async function grpcPrepareImportedKeyDWalletVerification(
	ikaClient: IkaGrpcClient,
	curve: Curve,
	bytesToHash: Uint8Array,
	senderAddress: string,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	privateKey: Uint8Array,
): Promise<ImportDWalletVerificationRequestInput> {
	const senderAddressBytes = bcs.Address.serialize(senderAddress).toBytes();
	const protocolPublicParameters = await ikaClient.getProtocolPublicParameters(undefined, curve);

	const [userSecretShare, userPublicOutput, userMessage] =
		await create_imported_dwallet_user_output(
			fromCurveToNumber(curve),
			protocolPublicParameters,
			sessionIdentifierDigest(bytesToHash, senderAddressBytes),
			privateKey,
		);

	const encryptedUserShareAndProof = await encryptSecretShare(
		curve,
		userSecretShare,
		userShareEncryptionKeys.encryptionKey,
		protocolPublicParameters,
	);

	return {
		userPublicOutput: Uint8Array.from(userPublicOutput),
		userMessage: Uint8Array.from(userMessage),
		encryptedUserShareAndProof: Uint8Array.from(encryptedUserShareAndProof),
	};
}
