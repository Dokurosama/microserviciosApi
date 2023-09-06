from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
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
app.title = "API para proyecto microservicios"

# Modelo Pydantic para la creación de usuarios
class UserCreate(BaseModel):
    name: str
    email: str

# Modelo Pydantic para la actualización de usuarios
class UserUpdate(BaseModel):
    name: str
    email: str

# Modelo Pydantic para la asignación de roles a usuarios
class UserRoleAssignment(BaseModel):
    user_id: int
    role_id: int

# Modelo Pydantic para la asignación de permisos a roles
class RolePermissionAssignment(BaseModel):
    role_id: int
    permission_id: int

# Modelo Pydantic para la creación de roles
class RoleCreate(BaseModel):
    role_name: str

# Modelo Pydantic para la creación de permisos
class PermissionCreate(BaseModel):
    permission_name: str

# Modelo Pydantic para la creación de acciones
class ActionCreate(BaseModel):
    action_name: str

# Modelo Pydantic para la creación de tablas afectadas
class AffectedTableCreate(BaseModel):
    table_name: str

# Modelo Pydantic para la creación de credenciales
class CredentialsCreate(BaseModel):
    user_id: int
    password_hash: str

# Modelo Pydantic para la creación de registros de historial
class HistoryCreate(BaseModel):
    user_id: int
    action_id: int
    table_id: int
    inserted_value: str
    updated_old_value: str
    updated_new_value: str
    deleted_value: str

# Conexión a la base de datos
conn = mysql.connector.connect(**db_config)
cursor = conn.cursor()

# Endpoint para crear un usuario
@app.post("/users/", response_model=dict, tags=["usuarios"])
async def create_user(user: UserCreate):
    try:
        query = "INSERT INTO users (name, email) VALUES (%s, %s)"
        values = (user.name, user.email)
        cursor.execute(query, values)
        conn.commit()
        return {"message": "Usuario creado exitosamente"}
    except Exception as e:
        return {"error": str(e)}

# Endpoint para obtener todos los usuarios
@app.get("/users/", response_model=list, tags=["usuarios"])
async def get_all_users(skip: int = Query(0, description="Número de elementos para omitir"), limit: int = Query(10, description="Número de elementos a recuperar")):
    try:
        query = "SELECT user_id, name, email FROM users LIMIT %s OFFSET %s"
        values = (limit, skip)
        cursor.execute(query, values)
        result = [{"user_id": user_id, "name": name, "email": email} for (user_id, name, email) in cursor.fetchall()]
        return result
    except Exception as e:
        return {"error": str(e)}

# Endpoint para obtener un usuario por ID
@app.get("/users/{user_id}", response_model=dict, tags=["usuarios"])
async def get_user_by_id(user_id: int):
    try:
        query = "SELECT user_id, name, email FROM users WHERE user_id = %s"
        values = (user_id,)
        cursor.execute(query, values)
        user = cursor.fetchone()
        if user:
            return {"user_id": user[0], "name": user[1], "email": user[2]}
        else:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
    except Exception as e:
        return {"error": str(e)}
    
# Endpoint para obtener usuarios por nombre
@app.get("/users/by_name/", response_model=list, tags=["usuarios"])
async def get_users_by_name(name: str = Query(..., description="Nombre del usuario a buscar")):
    try:
        query = "SELECT user_id, name, email FROM users WHERE name = %s"
        values = (name,)
        cursor.execute(query, values)
        result = [{"user_id": user_id, "name": name, "email": email} for (user_id, name, email) in cursor.fetchall()]
        return result
    except Exception as e:
        return {"error": str(e)}

# Endpoint para actualizar un usuario por ID
@app.put("/users/{user_id}", response_model=dict, tags=["usuarios"])
async def update_user(user_id: int, user: UserUpdate):
    try:
        query = "UPDATE users SET name = %s, email = %s WHERE user_id = %s"
        values = (user.name, user.email, user_id)
        cursor.execute(query, values)
        conn.commit()
        if cursor.rowcount > 0:
            return {"message": "Usuario actualizado exitosamente"}
        else:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
    except Exception as e:
        return {"error": str(e)}

# Endpoint para eliminar un usuario por ID
@app.delete("/users/{user_id}", response_model=dict, tags=["usuarios"])
async def delete_user(user_id: int):
    try:
        query = "DELETE FROM users WHERE user_id = %s"
        values = (user_id,)
        cursor.execute(query, values)
        conn.commit()
        if cursor.rowcount > 0:
            return {"message": "Usuario eliminado exitosamente"}
        else:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
    except Exception as e:
        return {"error": str(e)}

# Endpoint para asignar un rol a un usuario
@app.post("/users/{user_id}/assign_role/", response_model=dict, tags=["usuarios"])
async def assign_role_to_user(user_id: int, role_assignment: UserRoleAssignment):
    try:
        query = "INSERT INTO user_role (user_id, role_id) VALUES (%s, %s)"
        values = (user_id, role_assignment.role_id)
        cursor.execute(query, values)
        conn.commit()
        return {"message": "Rol asignado exitosamente"}
    except Exception as e:
        return {"error": str(e)}

# Endpoint para asignar un permiso a un rol
@app.post("/roles/{role_id}/assign_permission/", response_model=dict, tags=["roles"])
async def assign_permission_to_role(role_id: int, permission_assignment: RolePermissionAssignment):
    try:
        query = "INSERT INTO role_permissions (role_id, permission_id) VALUES (%s, %s)"
        values = (role_id, permission_assignment.permission_id)
        cursor.execute(query, values)
        conn.commit()
        return {"message": "Permiso asignado exitosamente al rol"}
    except Exception as e:
        return {"error": str(e)}

# Endpoint para crear un rol
@app.post("/roles/", response_model=dict, tags=["roles"])
async def create_role(role: RoleCreate):
    try:
        query = "INSERT INTO role (role_name) VALUES (%s)"
        values = (role.role_name,)
        cursor.execute(query, values)
        conn.commit()
        return {"message": "Rol creado exitosamente"}
    except Exception as e:
        return {"error": str(e)}

# Endpoint para crear un permiso
@app.post("/permissions/", response_model=dict, tags=["permisos"])
async def create_permission(permission: PermissionCreate):
    try:
        query = "INSERT INTO permissions (permission_name) VALUES (%s)"
        values = (permission.permission_name,)
        cursor.execute(query, values)
        conn.commit()
        return {"message": "Permiso creado exitosamente"}
    except Exception as e:
        return {"error": str(e)}

# Endpoint para crear una acción
@app.post("/actions/", response_model=dict, tags=["acciones"])
async def create_action(action: ActionCreate):
    try:
        query = "INSERT INTO actions (action_name) VALUES (%s)"
        values = (action.action_name,)
        cursor.execute(query, values)
        conn.commit()
        return {"message": "Acción creada exitosamente"}
    except Exception as e:
        return {"error": str(e)}

# Endpoint para crear una tabla afectada
@app.post("/affected_tables/", response_model=dict, tags=["tablas_afectadas"])
async def create_affected_table(affected_table: AffectedTableCreate):
    try:
        query = "INSERT INTO affected_tables (table_name) VALUES (%s)"
        values = (affected_table.table_name,)
        cursor.execute(query, values)
        conn.commit()
        return {"message": "Tabla afectada creada exitosamente"}
    except Exception as e:
        return {"error": str(e)}

# Endpoint para crear credenciales
@app.post("/credentials/", response_model=dict, tags=["credenciales"])
async def create_credentials(credentials: CredentialsCreate):
    try:
        query = "INSERT INTO credentials (user_id, password_hash) VALUES (%s, %s)"
        values = (credentials.user_id, credentials.password_hash)
        cursor.execute(query, values)
        conn.commit()
        return {"message": "Credenciales creadas exitosamente"}
    except Exception as e:
        return {"error": str(e)}

# Endpoint para crear registros de historial
@app.post("/history/", response_model=dict, tags=["historial"])
async def create_history(history: HistoryCreate):
    try:
        query = "INSERT INTO history (user_id, action_id, table_id, inserted_value, updated_old_value, updated_new_value, deleted_value) VALUES (%s, %s, %s, %s, %s, %s, %s)"
        values = (
            history.user_id,
            history.action_id,
            history.table_id,
            history.inserted_value,
            history.updated_old_value,
            history.updated_new_value,
            history.deleted_value,
        )
        cursor.execute(query, values)
        conn.commit()
        return {"message": "Registro de historial creado exitosamente"}
    except Exception as e:
        return {"error": str(e)}

# Endpoint para obtener todos los roles
@app.get("/roles/", response_model=list, tags=["roles"])
async def get_all_roles():
    try:
        query = "SELECT role_id, role_name FROM role"
        cursor.execute(query)
        result = [{"role_id": role_id, "role_name": role_name} for (role_id, role_name) in cursor.fetchall()]
        return result
    except Exception as e:
        return {"error": str(e)}

# Endpoint para obtener todos los permisos
@app.get("/permissions/", response_model=list, tags=["permisos"])
async def get_all_permissions():
    try:
        query = "SELECT permission_id, permission_name FROM permissions"
        cursor.execute(query)
        result = [{"permission_id": permission_id, "permission_name": permission_name} for (permission_id, permission_name) in cursor.fetchall()]
        return result
    except Exception as e:
        return {"error": str(e)}

# Endpoint para obtener todas las acciones
@app.get("/actions/", response_model=list, tags=["acciones"])
async def get_all_actions():
    try:
        query = "SELECT action_id, action_name FROM actions"
        cursor.execute(query)
        result = [{"action_id": action_id, "action_name": action_name} for (action_id, action_name) in cursor.fetchall()]
        return result
    except Exception as e:
        return {"error": str(e)}

# Endpoint para obtener todas las tablas afectadas
@app.get("/affected_tables/", response_model=list, tags=["tablas_afectadas"])
async def get_all_affected_tables():
    try:
        query = "SELECT table_id, table_name FROM affected_tables"
        cursor.execute(query)
        result = [{"table_id": table_id, "table_name": table_name} for (table_id, table_name) in cursor.fetchall()]
        return result
    except Exception as e:
        return {"error": str(e)}

# Endpoint para obtener todas las credenciales
@app.get("/credentials/", response_model=list, tags=["credenciales"])
async def get_all_credentials():
    try:
        query = "SELECT user_id, password_hash FROM credentials"
        cursor.execute(query)
        result = [{"user_id": user_id, "password_hash": password_hash} for (user_id, password_hash) in cursor.fetchall()]
        return result
    except Exception as e:
        return {"error": str(e)}

# Endpoint para obtener todos los registros de historial
@app.get("/history/", response_model=list, tags=["historial"])
async def get_all_history():
    try:
        query = "SELECT history_id, user_id, action_id, table_id, inserted_value, updated_old_value, updated_new_value, deleted_value FROM history"
        cursor.execute(query)
        result = [{"history_id": history_id, "user_id": user_id, "action_id": action_id, "table_id": table_id, "inserted_value": inserted_value, "updated_old_value": updated_old_value, "updated_new_value": updated_new_value, "deleted_value": deleted_value} for (history_id, user_id, action_id, table_id, inserted_value, updated_old_value, updated_new_value, deleted_value) in cursor.fetchall()]
        return result
    except Exception as e:
        return {"error": str(e)}
    
# Endpoint para eliminar un rol por ID
@app.delete("/roles/{role_id}", response_model=dict, tags=["roles"])
async def delete_role(role_id: int):
    try:
        query = "DELETE FROM role WHERE role_id = %s"
        values = (role_id,)
        cursor.execute(query, values)
        conn.commit()
        if cursor.rowcount > 0:
            return {"message": "Rol eliminado exitosamente"}
        else:
            raise HTTPException(status_code=404, detail="Rol no encontrado")
    except Exception as e:
        return {"error": str(e)}

# Endpoint para eliminar un permiso por ID
@app.delete("/permissions/{permission_id}", response_model=dict, tags=["permisos"])
async def delete_permission(permission_id: int):
    try:
        query = "DELETE FROM permissions WHERE permission_id = %s"
        values = (permission_id,)
        cursor.execute(query, values)
        conn.commit()
        if cursor.rowcount > 0:
            return {"message": "Permiso eliminado exitosamente"}
        else:
            raise HTTPException(status_code=404, detail="Permiso no encontrado")
    except Exception as e:
        return {"error": str(e)}

# Endpoint para eliminar una acción por ID
@app.delete("/actions/{action_id}", response_model=dict, tags=["acciones"])
async def delete_action(action_id: int):
    try:
        query = "DELETE FROM actions WHERE action_id = %s"
        values = (action_id,)
        cursor.execute(query, values)
        conn.commit()
        if cursor.rowcount > 0:
            return {"message": "Acción eliminada exitosamente"}
        else:
            raise HTTPException(status_code=404, detail="Acción no encontrada")
    except Exception as e:
        return {"error": str(e)}

# Endpoint para eliminar una tabla afectada por ID
@app.delete("/affected_tables/{table_id}", response_model=dict, tags=["tablas_afectadas"])
async def delete_affected_table(table_id: int):
    try:
        query = "DELETE FROM affected_tables WHERE table_id = %s"
        values = (table_id,)
        cursor.execute(query, values)
        conn.commit()
        if cursor.rowcount > 0:
            return {"message": "Tabla afectada eliminada exitosamente"}
        else:
            raise HTTPException(status_code=404, detail="Tabla afectada no encontrada")
    except Exception as e:
        return {"error": str(e)}

# Endpoint para eliminar credenciales por ID
@app.delete("/credentials/{user_id}", response_model=dict, tags=["credenciales"])
async def delete_credentials(user_id: int):
    try:
        query = "DELETE FROM credentials WHERE user_id = %s"
        values = (user_id,)
        cursor.execute(query, values)
        conn.commit()
        if cursor.rowcount > 0:
            return {"message": "Credenciales eliminadas exitosamente"}
        else:
            raise HTTPException(status_code=404, detail="Credenciales no encontradas")
    except Exception as e:
        return {"error": str(e)}

# Endpoint para eliminar un registro de historial por ID
@app.delete("/history/{history_id}", response_model=dict, tags=["historial"])
async def delete_history(history_id: int):
    try:
        query = "DELETE FROM history WHERE history_id = %s"
        values = (history_id,)
        cursor.execute(query, values)
        conn.commit()
        if cursor.rowcount > 0:
            return {"message": "Registro de historial eliminado exitosamente"}
        else:
            raise HTTPException(status_code=404, detail="Registro de historial no encontrado")
    except Exception as e:
        return {"error": str(e)}
    
# Endpoint para actualizar un rol por ID
@app.put("/roles/{role_id}", response_model=dict, tags=["roles"])
async def update_role(role_id: int, role: RoleCreate):
    try:
        query = "UPDATE role SET role_name = %s WHERE role_id = %s"
        values = (role.role_name, role_id)
        cursor.execute(query, values)
        conn.commit()
        if cursor.rowcount > 0:
            return {"message": "Rol actualizado exitosamente"}
        else:
            raise HTTPException(status_code=404, detail="Rol no encontrado")
    except Exception as e:
        return {"error": str(e)}

# Endpoint para actualizar un permiso por ID
@app.put("/permissions/{permission_id}", response_model=dict, tags=["permisos"])
async def update_permission(permission_id: int, permission: PermissionCreate):
    try:
        query = "UPDATE permissions SET permission_name = %s WHERE permission_id = %s"
        values = (permission.permission_name, permission_id)
        cursor.execute(query, values)
        conn.commit()
        if cursor.rowcount > 0:
            return {"message": "Permiso actualizado exitosamente"}
        else:
            raise HTTPException(status_code=404, detail="Permiso no encontrado")
    except Exception as e:
        return {"error": str(e)}

# Endpoint para actualizar una acción por ID
@app.put("/actions/{action_id}", response_model=dict, tags=["acciones"])
async def update_action(action_id: int, action: ActionCreate):
    try:
        query = "UPDATE actions SET action_name = %s WHERE action_id = %s"
        values = (action.action_name, action_id)
        cursor.execute(query, values)
        conn.commit()
        if cursor.rowcount > 0:
            return {"message": "Acción actualizada exitosamente"}
        else:
            raise HTTPException(status_code=404, detail="Acción no encontrada")
    except Exception as e:
        return {"error": str(e)}

# Endpoint para actualizar una tabla afectada por ID
@app.put("/affected_tables/{table_id}", response_model=dict, tags=["tablas_afectadas"])
async def update_affected_table(table_id: int, affected_table: AffectedTableCreate):
    try:
        query = "UPDATE affected_tables SET table_name = %s WHERE table_id = %s"
        values = (affected_table.table_name, table_id)
        cursor.execute(query, values)
        conn.commit()
        if cursor.rowcount > 0:
            return {"message": "Tabla afectada actualizada exitosamente"}
        else:
            raise HTTPException(status_code=404, detail="Tabla afectada no encontrada")
    except Exception as e:
        return {"error": str(e)}

# Endpoint para actualizar credenciales por ID
@app.put("/credentials/{user_id}", response_model=dict, tags=["credenciales"])
async def update_credentials(user_id: int, credentials: CredentialsCreate):
    try:
        query = "UPDATE credentials SET password_hash = %s WHERE user_id = %s"
        values = (credentials.password_hash, user_id)
        cursor.execute(query, values)
        conn.commit()
        if cursor.rowcount > 0:
            return {"message": "Credenciales actualizadas exitosamente"}
        else:
            raise HTTPException(status_code=404, detail="Credenciales no encontradas")
    except Exception as e:
        return {"error": str(e)}

# Endpoint para actualizar un registro de historial por ID
@app.put("/history/{history_id}", response_model=dict, tags=["historial"])
async def update_history(history_id: int, history: HistoryCreate):
    try:
        query = "UPDATE history SET user_id = %s, action_id = %s, table_id = %s, inserted_value = %s, updated_old_value = %s, updated_new_value = %s, deleted_value = %s WHERE history_id = %s"
        values = (
            history.user_id,
            history.action_id,
            history.table_id,
            history.inserted_value,
            history.updated_old_value,
            history.updated_new_value,
            history.deleted_value,
            history_id,
        )
        cursor.execute(query, values)
        conn.commit()
        if cursor.rowcount > 0:
            return {"message": "Registro de historial actualizado exitosamente"}
        else:
            raise HTTPException(status_code=404, detail="Registro de historial no encontrado")
    except Exception as e:
        return {"error": str(e)}

# Cerrar la conexión a la base de datos cuando se detiene la aplicación
@app.on_event("shutdown")
async def shutdown_db_connection():
    conn.close()