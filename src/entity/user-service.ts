import { AppDataSource } from '../data-source.ts';
import { User } from './user.ts';

export class UserService {
  private static repository = AppDataSource.getRepository(User);
  
  static async createUser(data: {
    username: string;
    email: string;
    password: string;
    role?: string;
  }): Promise<User> {
    const user = this.repository.create(data);
    return this.repository.save(user);
  }
  
  static async deleteUser(data: { id: number }): Promise<void> {
    await this.repository.delete(data.id);
  }

  static getUserByEmail(email: string) {
    return this.repository.findOne({
      where: { email },
    });
  }
}