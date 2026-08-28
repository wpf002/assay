-- The occurrence's own logical system. Added nullable and backfilled from the
-- System row the scan was filed under, which is exactly what reads returned
-- before this column existed, then made required.
ALTER TABLE "Occurrence" ADD COLUMN "systemKey" TEXT;

UPDATE "Occurrence" AS o
SET "systemKey" = s."name"
FROM "System" AS s
WHERE s."id" = o."systemId";

ALTER TABLE "Occurrence" ALTER COLUMN "systemKey" SET NOT NULL;

-- CreateTable
CREATE TABLE "ScanAsset" (
    "scanId" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,

    CONSTRAINT "ScanAsset_pkey" PRIMARY KEY ("scanId","assetId")
);

-- CreateIndex
CREATE INDEX "ScanAsset_assetId_idx" ON "ScanAsset"("assetId");

-- AddForeignKey
ALTER TABLE "ScanAsset" ADD CONSTRAINT "ScanAsset_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanAsset" ADD CONSTRAINT "ScanAsset_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "CryptoAsset"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- Backfill the declared-asset set from what is recoverable: the assets that
-- occurrences reference. Assets a past scan declared without an occurrence
-- were never linked to it and cannot be recovered here.
INSERT INTO "ScanAsset" ("scanId", "assetId")
SELECT DISTINCT "scanId", "assetId" FROM "Occurrence";
