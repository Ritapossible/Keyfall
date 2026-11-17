// Shared helpers for Keyfall scripts.
import { readFileSync, existsSync } from 'node:fs';
import { createPublicClient, createWalletClient, http, defineChain } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { bech32 } from '@scure/base';
import solc from 'solc';

export const RPC = process.env.QORE_EVM_RPC ?? 'https://evm-testnet.qore.host';
export const qore = defineChain({
  id: 9800, name: 'QoreChain testnet (diana)',
  nativeCurrency: { name: 'QOR', symbol: 'QOR', decimals: 18 },
  rpcUrls: { default: { http: [RPC] } },
});
export const publicClient = createPublicClient({ chain: qore, transport: http(RPC) });

export const KEYS = new URL('../keys/', import.meta.url);
export const readJson = (name) => JSON.parse(readFileSync(new URL(name, KEYS), 'utf8'));
export const hasKey = (name) => existsSync(new URL(name, KEYS));

export function deployer() {
  const { privateKey } = readJson('deployer.json');
  const account = privateKeyToAccount(privateKey);
  return { account, wallet: createWalletClient({ account, chain: qore, transport: http(RPC) }) };
}

export function mldsa() {
  const k = readJson('registry-mldsa87.json');
  return { publicKey: Uint8Array.from(Buffer.from(k.publicKey, 'hex')), secretKey: Uint8Array.from(Buffer.from(k.secretKey, 'hex')) };
}

export const toQor = (addr) => bech32.encode('qor', bech32.toWords(Buffer.from(addr.slice(2), 'hex')));

export function compileRegistry() {
  const src = readFileSync(new URL('../src/KeyfallRegistry.sol', import.meta.url), 'utf8');
  const input = {
    language: 'Solidity',
    sources: { 'KeyfallRegistry.sol': { content: src } },
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: 'paris',
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } },
  };
  const out = JSON.parse(solc.compile(JSON.stringify(input)));
  const errs = (out.errors ?? []).filter((e) => e.severity === 'error');
  if (errs.length) throw new Error(errs.map((e) => e.formattedMessage).join('\n'));
  const c = out.contracts['KeyfallRegistry.sol'].KeyfallRegistry;
  return { abi: c.abi, bytecode: `0x${c.evm.bytecode.object}` };
}
