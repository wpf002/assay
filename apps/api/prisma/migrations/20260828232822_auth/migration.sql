-- CreateTable
CREATE TABLE "ApiToken" (
    "id" TEXT NOT NULL,
    "secretHash" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "role" TEXT NOT NULL,
    "systems" TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdBy" TEXT NOT NULL,
    "lastUsedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "ApiToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditEvent" (
    "id" TEXT NOT NULL,
    "at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "tokenId" TEXT,
    "tokenName" TEXT NOT NULL,
    "role" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "route" TEXT NOT NULL,
    "resource" TEXT,
    "statusCode" INTEGER NOT NULL,
    "remoteAddr" TEXT NOT NULL,

    CONSTRAINT "AuditEvent_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ApiToken_secretHash_key" ON "ApiToken"("secretHash");

-- CreateIndex
CREATE INDEX "ApiToken_revokedAt_idx" ON "ApiToken"("revokedAt");

-- CreateIndex
CREATE INDEX "AuditEvent_at_idx" ON "AuditEvent"("at");

-- CreateIndex
CREATE INDEX "AuditEvent_tokenId_at_idx" ON "AuditEvent"("tokenId", "at");
