package com.pennywise.authService.db_entities;

import jakarta.persistence.*;
import org.antlr.v4.runtime.misc.NotNull;

import java.time.Instant;
import java.time.LocalDateTime;

@Entity
@Table(name = "users")
public class UserEntity {

        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        public int id;

        @Column(nullable = false)
        public String name;

        @NotNull
        @Column(nullable = false, unique = true)
        public String email;

        @Column(name = "pass_hash" ,nullable = false)
        public String password;

        @Column(name = "created_at", nullable = false, updatable = false, insertable = false)
        public Instant createdAt; //= Instant.now();

        @Column(name = "is_verified", nullable = false)
        public Boolean isVerified = false;

        public int getId() {
                return id;
        }

        public void setId(int id) {
                this.id = id;
        }

        public String getEmail() {
                return email;
        }

        public void setEmail(String email) {
                this.email = email;
        }

        public String getPassword() {
                return password;
        }

        public void setPassword(String password) {
                this.password = password;
        }

        public Instant getCreatedAt() {
                return createdAt;
        }

        public void setCreatedAt(Instant createdAt) {
                this.createdAt = createdAt;
        }

        public Boolean getVerified() {
                return isVerified;
        }

        public void setVerified(Boolean verified) {
                isVerified = verified;
        }

        public String getName() {
                return name;
        }

        public void setName(String name) {
                this.name = name;
        }

}
