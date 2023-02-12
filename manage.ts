import { DatabaseHandler } from "./database.js";
import bcrypt from 'bcrypt';
import { default as config } from './config.js';
import { readdir, unlink } from "fs/promises";
import { join as joinPath } from "path";


if (process.argv.length < 3) {
    console.log`
echost-manage <subcommand>

AVAILABLE COMMANDS

    adduser <username> <password>   adds a user
    deluser <username>              delete a user and hide their files
    setpass <username> <password>   change a users password
    delfile <username> <filename>   delete a specific file
    cleanup                         delete orphaned files
`
    process.exit(1)
}




const database = await DatabaseHandler.connect();
const actions = {
    async adduser(username: string, password: string) {
        if (await database.getPasswordHash(username)) {
            console.log(`User ${username} already exists`)
        } else {
            const passwordHash = await bcrypt.hash(password, 10);
            await database.createUser(username, passwordHash);
            console.log(`Created user ${username}`);
        }
    },
    async deluser(username: string) {
        if (await database.getPasswordHash(username)) {
            await database.deleteUser(username);
            console.log(`Deleted user ${username}. Run echost-manage cleanup to delete orphaned files`);
        } else {
            console.log(`User ${username} not found.`)
        }
    },
    async setpass(username: string, password: string) {
        if (await database.getPasswordHash(username)) {
            const passwordHash = await bcrypt.hash(password, 10);
            await database.setPasswordHash(username, passwordHash);
            console.log(`Password of user ${username} updated.`)
        } else {
            console.log(`User ${username} not found.`)
        }
    },
    async delfile(username: string, filename: string) {
        await database.deleteFileByName(username, filename);
        console.log(`File ${username}/${filename} deleted`)
    },
    async cleanup() {
        for (const path of await readdir(config.fileStorage)) {
            const name = await database.findOwnerByPath(path);
            if (!name) {
                console.log(`Deleting orphaned file ${path}`)
                await unlink(joinPath(config.fileStorage, path));
            }
        }
        console.log("Cleanup done")
    },

}

const action = process.argv[2];

if (action in actions) {
    await actions[action](...process.argv.splice(3))
} else {
    console.log("Subcommand not found. Invoke without arguments to see options")
}

