-- CreateTable
CREATE TABLE "System" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "owner" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "System_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CryptoAsset" (
    "id" TEXT NOT NULL,
    "primitive" TEXT NOT NULL,
    "parameters" JSONB NOT NULL,
    "purpose" TEXT NOT NULL,
    "quantumVulnerable" BOOLEAN NOT NULL,
    "classicalSecurityBits" INTEGER,
    "nistQuantumSecurityLevel" INTEGER,
    "oid" TEXT,

    CONSTRAINT "CryptoAsset_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Occurrence" (
    "id" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "systemId" TEXT NOT NULL,
    "controlClass" TEXT NOT NULL,
    "reachable" BOOLEAN,
    "reachVia" TEXT,
    "reachEntryPoint" TEXT,
    "reachPath" JSONB,
    "reachFactor" JSONB,
    "confidence" DECIMAL(6,4) NOT NULL,
    "confidenceFactor" JSONB NOT NULL,
    "assertionLevel" TEXT NOT NULL,
    "downgradeReason" TEXT,
    "urgencyTrack" TEXT,
    "moscaSlackYears" DECIMAL(6,2),
    "crqcSlackYears" DECIMAL(6,2),
    "regulatorySlackYears" DECIMAL(6,2),
    "bindingConstraint" TEXT,
    "moscaFactor" JSONB,
    "scanId" TEXT NOT NULL,

    CONSTRAINT "Occurrence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Evidence" (
    "id" TEXT NOT NULL,
    "occurrenceId" TEXT NOT NULL,
    "modality" TEXT NOT NULL,
    "locator" TEXT NOT NULL,
    "raw" TEXT NOT NULL,
    "collectedAt" TIMESTAMP(3) NOT NULL,
    "collectorVersion" TEXT NOT NULL,
    "location" TEXT,
    "line" INTEGER,
    "offset" INTEGER,
    "symbol" TEXT,

    CONSTRAINT "Evidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Scan" (
    "id" TEXT NOT NULL,
    "systemName" TEXT NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finishedAt" TIMESTAMP(3),
    "detectors" TEXT[],
    "policyPackId" TEXT NOT NULL,
    "policyPackVersion" TEXT NOT NULL,
    "scopeGrantId" TEXT,

    CONSTRAINT "Scan_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "System_name_kind_key" ON "System"("name", "kind");

-- CreateIndex
CREATE INDEX "CryptoAsset_quantumVulnerable_purpose_idx" ON "CryptoAsset"("quantumVulnerable", "purpose");

-- CreateIndex
CREATE INDEX "Occurrence_systemId_assertionLevel_idx" ON "Occurrence"("systemId", "assertionLevel");

-- CreateIndex
CREATE INDEX "Occurrence_urgencyTrack_moscaSlackYears_idx" ON "Occurrence"("urgencyTrack", "moscaSlackYears");

-- CreateIndex
CREATE INDEX "Occurrence_scanId_assetId_idx" ON "Occurrence"("scanId", "assetId");

-- CreateIndex
CREATE UNIQUE INDEX "Occurrence_scanId_id_key" ON "Occurrence"("scanId", "id");

-- CreateIndex
CREATE INDEX "Evidence_occurrenceId_idx" ON "Evidence"("occurrenceId");

-- CreateIndex
CREATE INDEX "Evidence_modality_idx" ON "Evidence"("modality");

-- CreateIndex
CREATE INDEX "Scan_systemName_startedAt_idx" ON "Scan"("systemName", "startedAt");

-- AddForeignKey
ALTER TABLE "Occurrence" ADD CONSTRAINT "Occurrence_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "CryptoAsset"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Occurrence" ADD CONSTRAINT "Occurrence_systemId_fkey" FOREIGN KEY ("systemId") REFERENCES "System"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Occurrence" ADD CONSTRAINT "Occurrence_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Evidence" ADD CONSTRAINT "Evidence_occurrenceId_fkey" FOREIGN KEY ("occurrenceId") REFERENCES "Occurrence"("id") ON DELETE CASCADE ON UPDATE CASCADE;
