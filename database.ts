
import sqlite3 from 'sqlite3';
import { open, Database } from 'sqlite';

export class DatabaseHandler {
    database: Database<sqlite3.Database, sqlite3.Statement>;
    constructor(database: Database) {
        this.database = database;
    }
    static async connect(): Promise<DatabaseHandler> {
        const db = await open({
            filename: 'database.db',
            driver: sqlite3.Database
        });
        return new DatabaseHandler(db);
    }

    async createTables(): Promise<void> {
        await this.database.run(`
            CREATE TABLE IF NOT EXISTS users (username TEXT, passwordHash TEXT);
        `);
        await this.database.run(`
            CREATE TABLE IF NOT EXISTS files (owner TEXT, filename TEXT, path TEXT);
        `)
    }

    async createUser(username: string, passwordHash: string): Promise<void> {
        await this.database.run(`
            INSERT INTO users (username, passwordHash) VALUES (?, ?);
        `, [username, passwordHash])
    }

    async createFile(owner: string, filename: string, path: string): Promise<void> {
        await this.database.run(`
            INSERT INTO files (owner, filename, path) VALUES (?,?,?);
        `, [owner, filename, path])
    }

    async renameFile(owner: string, path: string, newFilename: string): Promise<void> {
        await this.database.run(`
            UPDATE files SET filename = ? WHERE owner = ? AND path = ?; 
        `, [newFilename, owner, path]);
    }

    async deleteFile(owner: string, path: string): Promise<void> {
        await this.database.run(`
            DELETE FROM files WHERE owner = ? AND path = ?;
        `, [owner, path]);
    }

    async getPathForFileName(owner: string, filename: string): Promise<string | null> {
        let row = await this.database.get(
            "SELECT path FROM files WHERE owner = ? and filename = ?;",
            [owner, filename]
        );
        if (!row) {
            return null;
        }
        return row['path'];
    }

    async getPasswordHash(username: string): Promise<string | null> {
        let row = await this.database.get(
            "SELECT passwordHash FROM users WHERE username = ?;",
            [username]
        );
        if (!row) {
            return null;
        }
        return row['passwordHash'];
    }


}




