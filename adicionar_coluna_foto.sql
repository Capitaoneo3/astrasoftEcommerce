-- Script para adicionar a coluna foto_perfil na tabela gestores
-- Execute este script caso a coluna ainda não exista

-- Adicionar coluna foto_perfil se ela não existir
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name = 'gestores' 
        AND column_name = 'foto_perfil'
    ) THEN
        ALTER TABLE gestores 
        ADD COLUMN foto_perfil VARCHAR(255);
    END IF;
END $$;
