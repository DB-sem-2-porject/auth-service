import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { DataSource } from 'typeorm'

const __dirname = dirname(fileURLToPath(import.meta.url))

export const AppDataSource = new DataSource({
    type: "postgres",
    host: "localhost",
    port: 5432,
    username: "postgres",
    password: "3255",
    database: "DB-project",
    entities: [join(__dirname, "entity/**/*.ts")], // исправлено
    migrations: [join(__dirname, "../migrations/**/*.ts")], // исправлено - migrations в корне проекта
    synchronize: false,
})

// export default AppDataSource