from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import List

import mysql.connector

# Configuración de la base de datos
db_config = {
    "host": "containers-us-west-79.railway.app",
    "user": "root",
    "password": "75DgymTryDDguAMwCa7U",
    "database": "railway",
    "port": 7227,
}

# Inicializar la aplicación FastAPI
app = FastAPI()
app.title = "Api para proyecto microservicios"

# Modelo de datos Pydantic para usuarios
class User(BaseModel):
    name: str
    email: str

class UserInDB(User):
    user_id: int

# Conexión a la base de datos
def get_db_connection():
    return mysql.connector.connect(**db_config)

# Método para crear un usuario
@app.post("/users/", response_model=UserInDB, tags=['Usuarios'])
def create_user(user: User):
    db = get_db_connection()
    cursor = db.cursor()
    insert_query = "INSERT INTO users (name, email) VALUES (%s, %s)"
    insert_data = (user.name, user.email)
    cursor.execute(insert_query, insert_data)
    db.commit()
    user_id = cursor.lastrowid
    cursor.close()
    db.close()
    return {"user_id": user_id, **user.dict()}

# Método para obtener todos los usuarios
@app.get("/users/", response_model=List[UserInDB], tags=['Usuarios'])
def get_all_users(skip: int = Query(0, alias="page", ge=0), limit: int = Query(10, le=100)):
    db = get_db_connection()
    cursor = db.cursor()
    select_query = "SELECT user_id, name, email FROM users LIMIT %s OFFSET %s"
    cursor.execute(select_query, (limit, skip))
    users = [dict(zip(["user_id", "name", "email"], row)) for row in cursor.fetchall()]
    cursor.close()
    db.close()
    return users

# Método para obtener un usuario por ID
@app.get("/users/{user_id}", response_model=UserInDB, tags=['Usuarios'])
def get_user_by_id(user_id: int):
    db = get_db_connection()
    cursor = db.cursor()
    select_query = "SELECT user_id, name, email FROM users WHERE user_id = %s"
    cursor.execute(select_query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    db.close()
    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return dict(zip(["user_id", "name", "email"], user))

# Método para actualizar un usuario
@app.put("/users/{user_id}", response_model=UserInDB, tags=['Usuarios'])
def update_user(user_id: int, user: User):
    db = get_db_connection()
    cursor = db.cursor()
    update_query = "UPDATE users SET name = %s, email = %s WHERE user_id = %s"
    update_data = (user.name, user.email, user_id)
    cursor.execute(update_query, update_data)
    db.commit()
    cursor.close()
    db.close()
    return {"user_id": user_id, **user.dict()}

# Método para eliminar un usuario
@app.delete("/users/{user_id}", response_model=dict, tags=['Usuarios'])
def delete_user(user_id: int):
    db = get_db_connection()
    cursor = db.cursor()
    delete_query = "DELETE FROM users WHERE user_id = %s"
    cursor.execute(delete_query, (user_id,))
    db.commit()
    cursor.close()
    db.close()
    return {"message": "Usuario eliminado correctamente"}

# Modelo de datos Pydantic para el historial
class History(BaseModel):
    user_id: int
    action: str
    timestamp: str

class HistoryInDB(History):
    history_id: int

# Conexión a la base de datos
def get_db_connection():
    return mysql.connector.connect(**db_config)

# Método para crear un registro en el historial
@app.post("/history/", response_model=HistoryInDB, tags=['Historial'])
def create_history(history: History):
    db = get_db_connection()
    cursor = db.cursor()
    insert_query = "INSERT INTO history (user_id, action, timestamp) VALUES (%s, %s, %s)"
    insert_data = (history.user_id, history.action, history.timestamp)
    cursor.execute(insert_query, insert_data)
    db.commit()
    history_id = cursor.lastrowid
    cursor.close()
    db.close()
    return {"history_id": history_id, **history.dict()}

# Método para obtener todos los registros del historial
@app.get("/history/", response_model=List[HistoryInDB], tags=['Historial'])
def get_all_history(skip: int = Query(0, alias="page", ge=0), limit: int = Query(10, le=100)):
    db = get_db_connection()
    cursor = db.cursor()
    select_query = "SELECT history_id, user_id, action, timestamp FROM history LIMIT %s OFFSET %s"
    cursor.execute(select_query, (limit, skip))
    history_records = [dict(zip(["history_id", "user_id", "action", "timestamp"], row)) for row in cursor.fetchall()]
    cursor.close()
    db.close()
    return history_records

# Método para obtener un registro del historial por ID
@app.get("/history/{history_id}", response_model=HistoryInDB, tags=['Historial'])
def get_history_by_id(history_id: int):
    db = get_db_connection()
    cursor = db.cursor()
    select_query = "SELECT history_id, user_id, action, timestamp FROM history WHERE history_id = %s"
    cursor.execute(select_query, (history_id,))
    history_record = cursor.fetchone()
    cursor.close()
    db.close()
    if history_record is None:
        raise HTTPException(status_code=404, detail="Registro de historial no encontrado")
    return dict(zip(["history_id", "user_id", "action", "timestamp"], history_record))

# Método para actualizar un registro del historial
@app.put("/history/{history_id}", response_model=HistoryInDB, tags=['Historial'])
def update_history(history_id: int, history: History):
    db = get_db_connection()
    cursor = db.cursor()
    update_query = "UPDATE history SET user_id = %s, action = %s, timestamp = %s WHERE history_id = %s"
    update_data = (history.user_id, history.action, history.timestamp, history_id)
    cursor.execute(update_query, update_data)
    db.commit()
    cursor.close()
    db.close()
    return {"history_id": history_id, **history.dict()}

# Método para eliminar un registro del historial
@app.delete("/history/{history_id}", response_model=dict, tags=['Historial'])
def delete_history(history_id: int):
    db = get_db_connection()
    cursor = db.cursor()
    delete_query = "DELETE FROM history WHERE history_id = %s"
    cursor.execute(delete_query, (history_id,))
    db.commit()
    cursor.close()
    db.close()
    return {"message": "Registro de historial eliminado correctamente"}

# Modelo de datos Pydantic para credenciales
class Credential(BaseModel):
    user_id: int
    password_hash: str

class CredentialInDB(Credential):
    credential_id: int

# Conexión a la base de datos
def get_db_connection():
    return mysql.connector.connect(**db_config)

# Método para crear una credencial
@app.post("/credentials/", response_model=CredentialInDB, tags=['Credenciales'])
def create_credential(credential: Credential):
    db = get_db_connection()
    cursor = db.cursor()
    insert_query = "INSERT INTO credentials (user_id, password_hash) VALUES (%s, %s)"
    insert_data = (credential.user_id, credential.password_hash)
    cursor.execute(insert_query, insert_data)
    db.commit()
    credential_id = cursor.lastrowid
    cursor.close()
    db.close()
    return {"credential_id": credential_id, **credential.dict()}

# Método para obtener todas las credenciales
@app.get("/credentials/", response_model=List[CredentialInDB], tags=['Credenciales'])
def get_all_credentials():
    db = get_db_connection()
    cursor = db.cursor()
    select_query = "SELECT credential_id, user_id, password_hash FROM credentials"
    cursor.execute(select_query)
    credentials = [dict(zip(["credential_id", "user_id", "password_hash"], row)) for row in cursor.fetchall()]
    cursor.close()
    db.close()
    return credentials

# Método para obtener una credencial por ID de usuario
@app.get("/credentials/{user_id}", response_model=CredentialInDB, tags=['Credenciales'])
def get_credential_by_user_id(user_id: int):
    db = get_db_connection()
    cursor = db.cursor()
    select_query = "SELECT credential_id, user_id, password_hash FROM credentials WHERE user_id = %s"
    cursor.execute(select_query, (user_id,))
    credential = cursor.fetchone()
    cursor.close()
    db.close()
    if credential is None:
        raise HTTPException(status_code=404, detail="Credencial no encontrada")
    return dict(zip(["credential_id", "user_id", "password_hash"], credential))

# Método para actualizar una credencial
@app.put("/credentials/{credential_id}", response_model=CredentialInDB, tags=['Credenciales'])
def update_credential(credential_id: int, credential: Credential):
    db = get_db_connection()
    cursor = db.cursor()
    update_query = "UPDATE credentials SET user_id = %s, password_hash = %s WHERE credential_id = %s"
    update_data = (credential.user_id, credential.password_hash, credential_id)
    cursor.execute(update_query, update_data)
    db.commit()
    cursor.close()
    db.close()
    return {"credential_id": credential_id, **credential.dict()}

# Método para eliminar una credencial
@app.delete("/credentials/{credential_id}", response_model=dict, tags=['Credenciales'])
def delete_credential(credential_id: int):
    db = get_db_connection()
    cursor = db.cursor()
    delete_query = "DELETE FROM credentials WHERE credential_id = %s"
    cursor.execute(delete_query, (credential_id,))
    db.commit()
    cursor.close()
    db.close()
    return {"message": "Credencial eliminada correctamente"}

# Modelo de datos Pydantic para user_role
class UserRole(BaseModel):
    user_id: int
    role_id: int

class UserRoleInDB(UserRole):
    # Puedes agregar campos adicionales aquí si es necesario
    user_role_id: int

# Conexión a la base de datos
def get_db_connection():
    return mysql.connector.connect(**db_config)

# Método para crear una relación user_role
@app.post("/user_role/", response_model=UserRoleInDB, tags=['Roles de usuario'])
def create_user_role(user_role: UserRole):
    db = get_db_connection()
    cursor = db.cursor()
    insert_query = "INSERT INTO user_role (user_id, role_id) VALUES (%s, %s)"
    insert_data = (user_role.user_id, user_role.role_id)
    cursor.execute(insert_query, insert_data)
    db.commit()
    user_role_id = cursor.lastrowid
    cursor.close()
    db.close()
    return {"user_role_id": user_role_id, **user_role.dict()}

# Método para obtener todas las relaciones user_role
@app.get("/user_role/", response_model=List[UserRoleInDB], tags=['Roles de usuario'])
def get_all_user_roles():
    db = get_db_connection()
    cursor = db.cursor()
    select_query = "SELECT user_role_id, user_id, role_id FROM user_role"
    cursor.execute(select_query)
    user_roles = [dict(zip(["user_role_id", "user_id", "role_id"], row)) for row in cursor.fetchall()]
    cursor.close()
    db.close()
    return user_roles

# Método para obtener relaciones user_role por ID de usuario
@app.get("/user_role/by_user_id/{user_id}", response_model=List[UserRoleInDB], tags=['Roles de usuario'])
def get_user_roles_by_user_id(user_id: int):
    db = get_db_connection()
    cursor = db.cursor()
    select_query = "SELECT user_role_id, user_id, role_id FROM user_role WHERE user_id = %s"
    cursor.execute(select_query, (user_id,))
    user_roles = [dict(zip(["user_role_id", "user_id", "role_id"], row)) for row in cursor.fetchall()]
    cursor.close()
    db.close()
    return user_roles

# Método para obtener relaciones user_role por ID de rol
@app.get("/user_role/by_role_id/{role_id}", response_model=List[UserRoleInDB], tags=['Roles de usuario'])
def get_user_roles_by_role_id(role_id: int):
    db = get_db_connection()
    cursor = db.cursor()
    select_query = "SELECT user_role_id, user_id, role_id FROM user_role WHERE role_id = %s"
    cursor.execute(select_query, (role_id,))
    user_roles = [dict(zip(["user_role_id", "user_id", "role_id"], row)) for row in cursor.fetchall()]
    cursor.close()
    db.close()
    return user_roles

# Método para eliminar una relación user_role
@app.delete("/user_role/{user_role_id}", response_model=dict, tags=['Roles de usuario'])
def delete_user_role(user_role_id: int):
    db = get_db_connection()
    cursor = db.cursor()
    delete_query = "DELETE FROM user_role WHERE user_role_id = %s"
    cursor.execute(delete_query, (user_role_id,))
    db.commit()
    cursor.close()
    db.close()
    return {"message": "Relación user_role eliminada correctamente"}

# Modelo de datos Pydantic para roles
class Role(BaseModel):
    role_name: str

class RoleInDB(Role):
    role_id: int

# Conexión a la base de datos
def get_db_connection():
    return mysql.connector.connect(**db_config)

# Método para crear un rol
@app.post("/roles/", response_model=RoleInDB, tags=['Roles'])
def create_role(role: Role):
    db = get_db_connection()
    cursor = db.cursor()
    insert_query = "INSERT INTO role (role_name) VALUES (%s)"
    insert_data = (role.role_name,)
    cursor.execute(insert_query, insert_data)
    db.commit()
    role_id = cursor.lastrowid
    cursor.close()
    db.close()
    return {"role_id": role_id, **role.dict()}

# Método para obtener todos los roles
@app.get("/roles/", response_model=List[RoleInDB], tags=['Roles'])
def get_all_roles():
    db = get_db_connection()
    cursor = db.cursor()
    select_query = "SELECT role_id, role_name FROM role"
    cursor.execute(select_query)
    roles = [dict(zip(["role_id", "role_name"], row)) for row in cursor.fetchall()]
    cursor.close()
    db.close()
    return roles

# Método para obtener un rol por ID
@app.get("/roles/{role_id}", response_model=RoleInDB, tags=['Roles'])
def get_role_by_id(role_id: int):
    db = get_db_connection()
    cursor = db.cursor()
    select_query = "SELECT role_id, role_name FROM role WHERE role_id = %s"
    cursor.execute(select_query, (role_id,))
    role = cursor.fetchone()
    cursor.close()
    db.close()
    if role is None:
        raise HTTPException(status_code=404, detail="Rol no encontrado")
    return dict(zip(["role_id", "role_name"], role))

# Método para actualizar un rol
@app.put("/roles/{role_id}", response_model=RoleInDB, tags=['Roles'])
def update_role(role_id: int, role: Role):
    db = get_db_connection()
    cursor = db.cursor()
    update_query = "UPDATE role SET role_name = %s WHERE role_id = %s"
    update_data = (role.role_name, role_id)
    cursor.execute(update_query, update_data)
    db.commit()
    cursor.close()
    db.close()
    return {"role_id": role_id, **role.dict()}

# Método para eliminar un rol
@app.delete("/roles/{role_id}", response_model=dict, tags=['Roles'])
def delete_role(role_id: int):
    db = get_db_connection()
    cursor = db.cursor()
    delete_query = "DELETE FROM role WHERE role_id = %s"
    cursor.execute(delete_query, (role_id,))
    db.commit()
    cursor.close()
    db.close()
    return {"message": "Rol eliminado correctamente"}

# Modelo de datos Pydantic para role_permissions
class RolePermission(BaseModel):
    role_id: int
    permission_id: int

class RolePermissionInDB(RolePermission):
    role_permission_id: int

# Conexión a la base de datos
def get_db_connection():
    return mysql.connector.connect(**db_config)

# Método para crear una relación role_permissions
@app.post("/role_permissions/", response_model=RolePermissionInDB, tags=['Permisos de rol'])
def create_role_permission(role_permission: RolePermission):
    db = get_db_connection()
    cursor = db.cursor()
    insert_query = "INSERT INTO role_permissions (role_id, permission_id) VALUES (%s, %s)"
    insert_data = (role_permission.role_id, role_permission.permission_id)
    cursor.execute(insert_query, insert_data)
    db.commit()
    role_permission_id = cursor.lastrowid
    cursor.close()
    db.close()
    return {"role_permission_id": role_permission_id, **role_permission.dict()}

# Método para obtener todas las relaciones role_permissions
@app.get("/role_permissions/", response_model=List[RolePermissionInDB], tags=['Permisos de rol'])
def get_all_role_permissions():
    db = get_db_connection()
    cursor = db.cursor()
    select_query = "SELECT role_permission_id, role_id, permission_id FROM role_permissions"
    cursor.execute(select_query)
    role_permissions = [dict(zip(["role_permission_id", "role_id", "permission_id"], row)) for row in cursor.fetchall()]
    cursor.close()
    db.close()
    return role_permissions

# Método para obtener relaciones role_permissions por ID de rol
@app.get("/role_permissions/by_role_id/{role_id}", response_model=List[RolePermissionInDB], tags=['Permisos de rol'])
def get_role_permissions_by_role_id(role_id: int):
    db = get_db_connection()
    cursor = db.cursor()
    select_query = "SELECT role_permission_id, role_id, permission_id FROM role_permissions WHERE role_id = %s"
    cursor.execute(select_query, (role_id,))
    role_permissions = [dict(zip(["role_permission_id", "role_id", "permission_id"], row)) for row in cursor.fetchall()]
    cursor.close()
    db.close()
    return role_permissions

# Método para obtener relaciones role_permissions por ID de permiso
@app.get("/role_permissions/by_permission_id/{permission_id}", response_model=List[RolePermissionInDB], tags=['Permisos de rol'])
def get_role_permissions_by_permission_id(permission_id: int):
    db = get_db_connection()
    cursor = db.cursor()
    select_query = "SELECT role_permission_id, role_id, permission_id FROM role_permissions WHERE permission_id = %s"
    cursor.execute(select_query, (permission_id,))
    role_permissions = [dict(zip(["role_permission_id", "role_id", "permission_id"], row)) for row in cursor.fetchall()]
    cursor.close()
    db.close()
    return role_permissions

# Método para eliminar una relación role_permissions
@app.delete("/role_permissions/{role_permission_id}", response_model=dict, tags=['Permisos de rol'])
def delete_role_permission(role_permission_id: int):
    db = get_db_connection()
    cursor = db.cursor()
    delete_query = "DELETE FROM role_permissions WHERE role_permission_id = %s"
    cursor.execute(delete_query, (role_permission_id,))
    db.commit()
    cursor.close()
    db.close()
    return {"message": "Relación role_permissions eliminada correctamente"}

# Modelo de datos Pydantic para permisos
class Permission(BaseModel):
    permission_name: str

class PermissionInDB(Permission):
    permission_id: int

# Conexión a la base de datos
def get_db_connection():
    return mysql.connector.connect(**db_config)

# Método para crear un permiso
@app.post("/permissions/", response_model=PermissionInDB, tags=['Permisos'])
def create_permission(permission: Permission):
    db = get_db_connection()
    cursor = db.cursor()
    insert_query = "INSERT INTO permissions (permission_name) VALUES (%s)"
    insert_data = (permission.permission_name,)
    cursor.execute(insert_query, insert_data)
    db.commit()
    permission_id = cursor.lastrowid
    cursor.close()
    db.close()
    return {"permission_id": permission_id, **permission.dict()}

# Método para obtener todos los permisos
@app.get("/permissions/", response_model=List[PermissionInDB], tags=['Permisos'])
def get_all_permissions():
    db = get_db_connection()
    cursor = db.cursor()
    select_query = "SELECT permission_id, permission_name FROM permissions"
    cursor.execute(select_query)
    permissions = [dict(zip(["permission_id", "permission_name"], row)) for row in cursor.fetchall()]
    cursor.close()
    db.close()
    return permissions

# Método para obtener un permiso por ID
@app.get("/permissions/{permission_id}", response_model=PermissionInDB, tags=['Permisos'])
def get_permission_by_id(permission_id: int):
    db = get_db_connection()
    cursor = db.cursor()
    select_query = "SELECT permission_id, permission_name FROM permissions WHERE permission_id = %s"
    cursor.execute(select_query, (permission_id,))
    permission = cursor.fetchone()
    cursor.close()
    db.close()
    if permission is None:
        raise HTTPException(status_code=404, detail="Permiso no encontrado")
    return dict(zip(["permission_id", "permission_name"], permission))

# Método para actualizar un permiso
@app.put("/permissions/{permission_id}", response_model=PermissionInDB, tags=['Permisos'])
def update_permission(permission_id: int, permission: Permission):
    db = get_db_connection()
    cursor = db.cursor()
    update_query = "UPDATE permissions SET permission_name = %s WHERE permission_id = %s"
    update_data = (permission.permission_name, permission_id)
    cursor.execute(update_query, update_data)
    db.commit()
    cursor.close()
    db.close()
    return {"permission_id": permission_id, **permission.dict()}

# Método para eliminar un permiso
@app.delete("/permissions/{permission_id}", response_model=dict, tags=['Permisos'])
def delete_permission(permission_id: int):
    db = get_db_connection()
    cursor = db.cursor()
    delete_query = "DELETE FROM permissions WHERE permission_id = %s"
    cursor.execute(delete_query, (permission_id,))
    db.commit()
    cursor.close()
    db.close()
    return {"message": "Permiso eliminado correctamente"}
