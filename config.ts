import { default as config } from './config.json' assert {type: 'json'};

export default config as {
    openRegistrations: boolean,
    usedPort: number,
    fileStorage: string,
    mimeTypeWhiteList: string[],
};