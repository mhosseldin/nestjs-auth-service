-- CreateEnum
CREATE TYPE "public"."EmailTicketType" AS ENUM ('VERIFY');

-- CreateTable
CREATE TABLE "public"."EmailTicket" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "type" "public"."EmailTicketType" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),

    CONSTRAINT "EmailTicket_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "EmailTicket_tokenHash_key" ON "public"."EmailTicket"("tokenHash");

-- CreateIndex
CREATE INDEX "EmailTicket_userId_idx" ON "public"."EmailTicket"("userId");

-- CreateIndex
CREATE INDEX "EmailTicket_expiresAt_idx" ON "public"."EmailTicket"("expiresAt");

-- AddForeignKey
ALTER TABLE "public"."EmailTicket" ADD CONSTRAINT "EmailTicket_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
