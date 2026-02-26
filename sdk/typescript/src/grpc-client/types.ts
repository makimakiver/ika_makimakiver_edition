// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// import type { SuiJsonClient } from '@mysten/sui/client';
import type { SuiGrpcClient } from '@mysten/sui/grpc';

import type { EncryptionKeyOptions, IkaConfig } from '../client/types.js';

/**
 * !!MODIFICATION!!
 *  Added IkaGrpcClientOptions so that users can create IkaGrpcClientOptions
 */
export interface IkaGrpcClientOptions {
	config: IkaConfig;
	suiClient: SuiGrpcClient;
	timeout?: number;
	protocolPublicParameters?: {
		networkEncryptionKeyPublicOutputID: string;
		epoch: number;
		protocolPublicParameters: Uint8Array;
	};
	cache?: boolean;
	/** Default encryption key options for the client */
	encryptionKeyOptions?: EncryptionKeyOptions;
}
