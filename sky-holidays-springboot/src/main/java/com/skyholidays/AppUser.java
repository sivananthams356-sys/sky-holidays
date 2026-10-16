package com.skyholidays;

/** Logged-in user stored in the session. role is "admin" or "client". */
public record AppUser(long id, String name, String email, String role) {}
