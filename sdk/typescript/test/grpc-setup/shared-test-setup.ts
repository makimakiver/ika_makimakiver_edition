// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { SuiGrpcClient } from '@mysten/sui/grpc';
import { SuiJsonRpcClient } from '@mysten/sui/jsonRpc';

import type { IkaClient } from '../../src/client/ika-client.js';
import type { UserShareEncryptionKeys } from '../../src/client/user-share-encryption-keys.js';
import { IkaGrpcClient } from '../../src/index.js';
import {
	createTestIkaClient,
	createTestIkaGrpcClient,
	createTestSuiGrpcClient,
	generateTestKeypair,
} from './test-utils.js';

// Shared test instances to reduce memory usage across all tests
export class SharedTestSetup {
	private static instance: SharedTestSetup | null = null;
	public suiClient: SuiGrpcClient | null = null;
	public ikaClient: IkaClient | null = null;

	// Added two extra public vars here
	public suiGrpcClient: SuiGrpcClient | null = null;
	public ikaGrpcClient: IkaGrpcClient | null = null;
	//

	public sharedKeypairs: Map<string, ReturnType<typeof generateTestKeypair>> = new Map();
	private initialized = false;
	private grpcInitialized = false;

	private constructor() {}

	/**
	 * Get the singleton instance of SharedTestSetup
	 */
	public static getInstance(): SharedTestSetup {
		if (!SharedTestSetup.instance) {
			SharedTestSetup.instance = new SharedTestSetup();
		}
		return SharedTestSetup.instance;
	}

	/**
	 * Getting same singleton instance of SharedTestSetup but grpc
	 */
	public static getGrpcInstance(): SharedTestSetup {
		if (!SharedTestSetup.instance) {
			SharedTestSetup.instance = new SharedTestSetup();
		}
		return SharedTestSetup.instance;
	}

	/**
	 * Initialize shared test instances
	 */
	public async initialize(): Promise<void> {
		if (this.grpcInitialized) {
			return;
		}

		this.suiGrpcClient = createTestSuiGrpcClient();
		this.ikaGrpcClient = createTestIkaGrpcClient(this.suiGrpcClient);
		await this.ikaGrpcClient.initialize();

		this.grpcInitialized = true;
	}

	/**
	 * Initialize shared gRPC test instances
	 */
	public async initializeGrpc(): Promise<void> {
		if (this.grpcInitialized) {
			return;
		}

		this.suiGrpcClient = createTestSuiGrpcClient();
		this.ikaGrpcClient = createTestIkaGrpcClient(this.suiGrpcClient);
		await this.ikaGrpcClient.initialize();

		this.grpcInitialized = true;
	}

	/**
	 * Check if the gRPC setup is initialized
	 */
	public isGrpcInitialized(): boolean {
		return this.grpcInitialized;
	}

	/**
	 * Get or create a shared keypair for a test
	 */
	public getSharedKeypair(testName: string): ReturnType<typeof generateTestKeypair> {
		if (!this.sharedKeypairs.has(testName)) {
			this.sharedKeypairs.set(testName, generateTestKeypair(testName));
		}
		return this.sharedKeypairs.get(testName)!;
	}

	/**
	 * Get shared IkaClient instance
	 */
	public getIkaClient(): IkaClient {
		if (!this.ikaClient) {
			throw new Error('SharedTestSetup not initialized. Call initialize() first.');
		}
		return this.ikaClient;
	}

	/**
	 * Get shared SuiGrpcClient instance
	 */
	public getSuiGrpcClient(): SuiGrpcClient {
		if (!this.suiGrpcClient) {
			throw new Error('SharedTestSetup not initialized. Call initialize() first.');
		}
		return this.suiGrpcClient;
	}

	/**
	 * Get shared IkaGrpcClient instance
	 */
	public getIkaGrpcClient(): IkaGrpcClient {
		if (!this.ikaGrpcClient) {
			throw new Error('SharedTestSetup not initialized. Call initialize() first.');
		}
		return this.ikaGrpcClient;
	}

	/**
	 * Check if the setup is initialized
	 */
	public isInitialized(): boolean {
		return this.initialized;
	}

	/**
	 * Clear all shared instances (for cleanup)
	 */
	public cleanup(): void {
		this.suiClient = null;
		this.ikaClient = null;
		this.suiGrpcClient = null;
		this.ikaGrpcClient = null;
		this.sharedKeypairs.clear();
		this.initialized = false;
		this.grpcInitialized = false;
	}

	/**
	 * Reset the singleton instance (mainly for testing)
	 */
	public static reset(): void {
		if (SharedTestSetup.instance) {
			SharedTestSetup.instance.cleanup();
		}
		SharedTestSetup.instance = null;
	}
}

/**
 * Helper function to get shared gRPC test setup
 */
export async function getSharedTestGrpcSetup(): Promise<SharedTestSetup> {
	const setup = SharedTestSetup.getGrpcInstance();
	if (!setup.isGrpcInitialized()) {
		await setup.initializeGrpc();
	}
	return setup;
}

/**
 * Same helper function but for grpc setting (for gas-consuming operations)
 */
export async function createGrpcIndividualTestSetup(testName: string) {
	const sharedSetup = await getSharedTestGrpcSetup();
	const { userShareEncryptionKeys, signerAddress, signerPublicKey, userKeypair } =
		await sharedSetup.getSharedKeypair(testName);

	return {
		suiClient: sharedSetup.getSuiGrpcClient(),
		ikaClient: sharedSetup.getIkaGrpcClient(),
		userShareEncryptionKeys,
		signerAddress,
		signerPublicKey,
		userKeypair,
	};
}
