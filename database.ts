
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
    }

    async createUser(username: string, passwordHash: string): Promise<void> {
        await this.database.run(`
            INSERT INTO users (username, passwordHash) VALUES (?, ?);
        `, [username, passwordHash])
    }

    async getPasswordHash(username: string): Promise<string | null> {
        let row = await this.database.get(
            "SELECT passwordHash FROM users WHERE username = ?;",
            [username]
        );
        console.log(row);
        if (!row) {
            return null;
        }
        return row['passwordHash'];
    }


}




