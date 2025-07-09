import { Injectable, Inject } from '@nestjs/common';
import { JwtService } from 'src/infrastructure/services/jwt.service';
import { SignInDto } from 'src/application/dtos/Authentication/sign-in.dto';
import { InvalidCredentialsError } from 'src/shared/errors/auth.errors';
import { IUserRepository } from 'src/domain/repositories/Authentication/user.repository';
import { throwError } from 'rxjs';
import { InjectRepository } from '@nestjs/typeorm';
import { TypeOrmUser } from 'src/infrastructure/database/entities/typeorm-user.entity';
import { Repository } from 'typeorm';
import { TypeOrmAdministrator } from 'src/infrastructure/database/entities/typeorm-administrator.entity';
import { Role } from 'src/domain/entities/role.entity';
import { IInstructorRepository } from 'src/domain/repositories/Users/instructor.repository';
import { IReceptionistRepository } from 'src/domain/repositories/Users/receptionist.repository';
import { IStudentRepository } from 'src/domain/repositories/Users/student.repository';
import { Administrator } from 'src/domain/entities/Users/administrator.entity';

@Injectable()
export class SignInUseCase {
  constructor(
    @Inject('IUserRepository')
    private readonly userRepository: IUserRepository,

    @Inject('IInstructorRepository')
    private readonly instructorRepository: IInstructorRepository,

    @Inject('IReceptionistRepository')
    private readonly receptionistRepository: IReceptionistRepository,

    @Inject('IStudentRepository')
    private readonly studentRepository: IStudentRepository,

    @InjectRepository(TypeOrmUser)
    private readonly userRepositoryTypeOrm: Repository<TypeOrmUser>,

    @InjectRepository(TypeOrmAdministrator)
    private readonly repository: Repository<TypeOrmAdministrator>,

    private readonly jwtService: JwtService,
  ) { }

  async execute(
    dto: SignInDto,
  ): Promise<{ accessToken: string; userData?: any }> {
    const email = dto.email;
    const password = dto.password;

    const user = await this.userRepository.validateCredentials(email, password);

    if (!user) {
      throw new InvalidCredentialsError();
    }

    const roleToSearch = await this.userRepository.validateRole(
      user.getRole().getId(),
    );
    if (!roleToSearch) {
      throwError(() => new Error('Role not found'));
      return { accessToken: '' };
    }

    let userData: any = null;

    if (roleToSearch == 'Student') {
      userData = await this.studentRepository.findByEmail(email);
    }
    if (roleToSearch == 'Administrator') {
      const TypeOrmUser = await this.userRepositoryTypeOrm.findOne({
        where: { email },
        relations: ['role'],
      });
      if (!TypeOrmUser) {
        throw new InvalidCredentialsError();
      }

      const TypeOrmAdministrator = await this.repository.findOne({
        where: { userId: TypeOrmUser.id },
        relations: ['role'],
      });
      if (!TypeOrmAdministrator) {
        throw new InvalidCredentialsError();
      }

      const role = TypeOrmAdministrator.role
        ? new Role(TypeOrmAdministrator.role.id, TypeOrmAdministrator.role.name, TypeOrmAdministrator.role.description)
            : undefined;

      userData = new Administrator(
        TypeOrmAdministrator.id,
        TypeOrmAdministrator.userId,
        TypeOrmAdministrator.CI,
        TypeOrmAdministrator.firstName,
        TypeOrmAdministrator.lastName,
        TypeOrmAdministrator.phone,
        role as Role,
        TypeOrmAdministrator.department, // Ejemplo: 'HR', 'Finance'
      );
    }
    if (roleToSearch == 'Instructor') {
      userData = await this.instructorRepository.findByEmail(email);
    }
    if (roleToSearch == 'Receptionist') {
      userData = await this.receptionistRepository.findByEmail(email);
    }

    const payload = {
      sub: user.getId(),
      email: user.getEmail(),
      roleId: user.getRole().getId(),
    };
    const accessToken = this.jwtService.sign(payload);
    return { accessToken, userData };
  }
}
