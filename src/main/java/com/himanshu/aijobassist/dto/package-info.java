/**
 * DTO Layer — Data Transfer Objects.
 *
 * DTOs control what data goes IN (request) and OUT (response) of the API.
 * They decouple your internal entity structure from the external API contract.
 *
 * Why DTOs matter:
 * - Security: Never expose sensitive fields like passwords
 * - Flexibility: API shape can evolve independently of the database schema
 * - Validation: Request DTOs carry validation annotations (@NotBlank, @Email)
 */
package com.himanshu.aijobassist.dto;
