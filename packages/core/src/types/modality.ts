/**
 * How a finding was observed. Modality determines the CONFIDENCE CEILING.
 * Repetition within a modality never raises confidence; only corroboration
 * across independent modalities does. This is the invariant (I1) that keeps
 * the CBOM signal-bearing.
 *
 * CycloneDX has a confidence FIELD (evidence.identity.confidence, 0-100) and
 * a six-value technique enum. It has no notion of a per-technique ceiling and
 * no notion of correlated vs independent evidence. That gap is the reason this
 * module exists.
 */
export const MODALITIES = [
  'SOURCE_AST', // parsed call site w/ resolved arguments
  'SOURCE_CONFIG', // nginx.conf, openssl.cnf, java.security, sshd_config
  'DEPENDENCY', // manifest entry -> known crypto capability surface. a hint, not a finding.
  'BINARY_SYMBOL', // imported/exported symbol table entry
  'BINARY_CONSTANT', // byte-exact algorithm constant (S-box, round const, curve param)
  'BINARY_STRING', // string match. weak. never sole basis for a CONFIRMED assertion.
  'HOST_AGENT', // endpoint agent / EDR telemetry: filesystem, registry, process memory
  'RUNTIME_HOOK', // instrumented process observed calling the primitive. independent of source.
  'NETWORK_ACTIVE', // negotiated handshake. ground truth for DEPLOYED, silent on CAPABILITY.
  'NETWORK_PASSIVE', // pcap observation
  'PKI_CERTIFICATE', // parsed X.509 / SSH host key
  'CLOUD_KMS_API', // authenticated KMS/HSM/KMIP enumeration. the provider names the key spec.
  'ASSERTED', // vendor questionnaire or human claim. unverified.
] as const;
export type Modality = (typeof MODALITIES)[number];

/**
 * Hard ceiling on confidence contributed by a single modality.
 *
 * DEPENDENCY sits at 0.35 (decision D1): a library SUPPORTING RSA is not
 * evidence that RSA is USED. Dependency evidence exists to direct AST scanning
 * and is exported as a CycloneDX `implements` relationship, never `uses`.
 */
export const MODALITY_CEILING: Record<Modality, number> = {
  SOURCE_AST: 0.95,
  SOURCE_CONFIG: 0.9,
  DEPENDENCY: 0.35,
  BINARY_SYMBOL: 0.85,
  BINARY_CONSTANT: 0.9,
  BINARY_STRING: 0.3,
  HOST_AGENT: 0.9,
  RUNTIME_HOOK: 0.97,
  NETWORK_ACTIVE: 0.98,
  NETWORK_PASSIVE: 0.8,
  PKI_CERTIFICATE: 0.99,
  CLOUD_KMS_API: 0.97,
  ASSERTED: 0.4,
};

/**
 * Modalities that are NOT independent of each other for corroboration purposes.
 * Every modality appears in exactly one group; the partition is total, and a
 * test enforces that. Confidence combines by noisy-OR ACROSS groups and by
 * max WITHIN a group.
 *
 * RUNTIME_HOOK is its own group on purpose: observing a live process call the
 * primitive is causally independent of having read the source that compiled
 * into it, so the two genuinely stack.
 */
export const CORRELATED_GROUPS: readonly (readonly Modality[])[] = [
  ['SOURCE_AST', 'SOURCE_CONFIG', 'DEPENDENCY'],
  ['BINARY_SYMBOL', 'BINARY_CONSTANT', 'BINARY_STRING', 'HOST_AGENT'],
  ['NETWORK_ACTIVE', 'NETWORK_PASSIVE'],
  ['PKI_CERTIFICATE', 'CLOUD_KMS_API'],
  ['RUNTIME_HOOK'],
  ['ASSERTED'],
];

/** Modalities that describe what is DEPLOYED rather than what is POSSIBLE. */
export const DEPLOYMENT_MODALITIES: ReadonlySet<Modality> = new Set<Modality>([
  'NETWORK_ACTIVE',
  'NETWORK_PASSIVE',
  'PKI_CERTIFICATE',
  'CLOUD_KMS_API',
  'RUNTIME_HOOK',
  'HOST_AGENT',
]);

/** Modalities that describe what a system is CAPABLE of, not what it runs. */
export const CAPABILITY_MODALITIES: ReadonlySet<Modality> = new Set<Modality>([
  'SOURCE_AST',
  'SOURCE_CONFIG',
  'DEPENDENCY',
  'BINARY_SYMBOL',
  'BINARY_CONSTANT',
  'BINARY_STRING',
  'ASSERTED',
]);
