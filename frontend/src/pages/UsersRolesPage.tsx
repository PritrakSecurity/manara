import React, { useState, useEffect } from 'react';
import { Plus, Trash2, Edit2, CheckCircle, XCircle, Users, Shield, ChevronDown } from 'lucide-react';
import { apiClient } from '../api/client';

interface User {
  id: string;
  username: string;
  email: string;
  first_name: string;
  last_name: string;
  is_active: boolean;
  is_ad_synced: boolean;
  source?: string; // 'local' or 'ad'
  status?: string; // 'active', 'inactive', 'suspended'
  roles?: Role[]; // Make roles optional since it might not be populated
  created_at: string;
  updated_at: string;
}

interface Role {
  id: string;
  name: string;
  description: string;
  is_system?: boolean;
  permissions: Permission[];
  created_at: string;
  updated_at: string;
}

interface Permission {
  id: string;
  name: string;
  resource: string;
  action: string;
  description: string;
  category?: string;
  is_implemented?: boolean;
}

interface ADUser {
  distinguished_name: string;
  username: string;
  email: string;
  full_name: string;
  department?: string;
  is_already_added: boolean;
}

export default function UsersRolesPage() {
  const [activeTab, setActiveTab] = useState<'users' | 'roles' | 'permissions'>('users');
  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [adUsers, setADUsers] = useState<ADUser[]>([]);
  const [adError, setADError] = useState<string | null>(null);
  
  const [showAddUserDropdown, setShowAddUserDropdown] = useState(false);
  
  // Local flags and UI state for permissions/roles mock
  const [showAddUserModal, setShowAddUserModal] = useState(false);
  const [showAddUserFromADModal, setShowAddUserFromADModal] = useState(false);
  const [showAddRoleModal, setShowAddRoleModal] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [editingRole, setEditingRole] = useState<Role | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [permissionsSearch, setPermissionsSearch] = useState('');
  const [permissionsCategoryFilter, setPermissionsCategoryFilter] = useState<string | 'All'>('All');
  const [selectedPermission, setSelectedPermission] = useState<Permission | null>(null);
  const [showPermissionModal, setShowPermissionModal] = useState(false);


  useEffect(() => {
    loadUsers();
    loadRoles();
    loadPermissions();
  }, []);

  const loadUsers = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get('/api/v1/users', { params: { limit: 100 } });
      setUsers(response.data.users || []);
    } catch (err) {
      console.warn('Failed to load users:', err);
      setError(err instanceof Error ? err.message : 'Failed to load users');
      setUsers([]);
    } finally {
      setLoading(false);
    }
  };

  const loadRoles = async () => {
    try {
      const response = await apiClient.get('/api/v1/roles');
      setRoles(response.data.roles || []);
    } catch (err) {
      console.warn('Failed to load roles:', err);
      setError(err instanceof Error ? err.message : 'Failed to load roles');
      setRoles([]);
    }
  };

  const loadPermissions = async () => {
    try {
      const response = await apiClient.get('/api/v1/permissions');
      setPermissions(response.data.permissions || []);
    } catch (err) {
      console.warn('Failed to load permissions:', err);
      setError(err instanceof Error ? err.message : 'Failed to load permissions');
      setPermissions([]);
    }
  };

  const loadADUsers = async () => {
    try {
      setADError(null);
      const response = await apiClient.get('/api/v1/ad/users');
      setADUsers(response.data.data || response.data.ad_users || []);
      setADError(null);
    } catch (err) {
      // Network or unexpected error - keep AD error local
      const msg = err instanceof Error ? err.message : 'Error loading AD users';
      setADUsers([]);
      setADError(msg);
    }
  };

  const handleSaveUser = async (formData: any) => {
    try {
      if (editingUser) {
        await apiClient.put(`/api/v1/users/${editingUser.id}`, formData);
      } else {
        await apiClient.post('/api/v1/users', formData);
      }

      setShowAddUserModal(false);
      setEditingUser(null);
      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error saving user');
    }
  };

  const handleSaveUserFromAD = async (ad_distinguished_name: string, role_ids: string[]) => {
    try {
      await apiClient.post('/api/v1/users/from-ad', { ad_distinguished_name, role_ids });

      setShowAddUserFromADModal(false);
      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error adding user from AD');
    }
  };

  const handleDeleteUser = async (userId: string) => {
    try {
      await apiClient.delete(`/api/v1/users/${userId}`);

      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error deleting user');
    }
  };

  const handleSaveRole = async (formData: any) => {
    try {
      if (editingRole) {
        await apiClient.put(`/api/v1/roles/${editingRole.id}`, formData);
      } else {
        await apiClient.post('/api/v1/roles', formData);
      }

      setShowAddRoleModal(false);
      setEditingRole(null);
      await loadRoles();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error saving role');
    }
  };

  const handleDeleteRole = async (roleId: string, isSystem: boolean) => {
    if (isSystem) {
      setError('System roles cannot be deleted');
      return;
    }

    try {
      await apiClient.delete(`/api/v1/roles/${roleId}`);

      await loadRoles();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error deleting role');
    }
  };

  return (
    <div className="p-6">

      <div className="flex gap-4 mb-6 border-b">
        {(['users', 'roles', 'permissions'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`pb-2 px-4 font-semibold ${
              activeTab === tab
                ? 'border-b-2 border-blue-600 text-blue-600'
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      {error && (
        <div className="mb-6 p-4 bg-red-50 border border-red-200 text-red-700 text-sm rounded">
          {error}
        </div>
      )}

      {activeTab === 'users' && (
        <div>
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-2xl font-bold">Users Management</h2>
            
            <div className="relative">
              <button
                onClick={() => setShowAddUserDropdown(!showAddUserDropdown)}
                className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
              >
                <Plus size={20} /> Add User <ChevronDown size={16} />
              </button>

              {showAddUserDropdown && (
                <div className="absolute right-0 mt-2 w-56 bg-white border rounded-lg shadow-lg z-10">
                  <button
                    onClick={() => { 
                      setShowAddUserDropdown(false);
                      setEditingUser(null); 
                      setShowAddUserModal(true); 
                    }}
                    className="w-full text-left px-4 py-3 hover:bg-gray-50 flex items-center gap-3"
                  >
                    <Users size={18} />
                    <div>
                      <div className="font-semibold">Manual User</div>
                      <div className="text-xs text-gray-500">Create local user account</div>
                    </div>
                  </button>
                  <button
                    onClick={() => { 
                      setShowAddUserDropdown(false);
                      loadADUsers();
                      setShowAddUserFromADModal(true);
                    }}
                    className="w-full text-left px-4 py-3 hover:bg-gray-50 flex items-center gap-3 border-t"
                  >
                    <Shield size={18} />
                    <div>
                      <div className="font-semibold">From Active Directory</div>
                      <div className="text-xs text-gray-500">Add synced AD user</div>
                    </div>
                  </button>
                </div>
              )}
            </div>
          </div>

          {loading ? (
            <div className="text-center py-12">
              <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-blue-600 border-t-transparent"></div>
              <p className="mt-2 text-gray-600">Loading users...</p>
            </div>
          ) : users.length === 0 ? (
            <div className="text-center py-12 bg-gray-50 rounded-lg">
              <Users size={48} className="mx-auto text-gray-400 mb-4" />
              <p className="text-gray-600 mb-4">No users found. Add one to get started.</p>
              <button
                onClick={() => { setEditingUser(null); setShowAddUserModal(true); }}
                className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
              >
                <Plus size={20} /> Add Your First User
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto bg-white rounded-lg border">
              <table className="w-full">
                <thead className="bg-gray-50 border-b">
                  <tr>
                    <th className="p-3 text-left font-semibold">Username</th>
                    <th className="p-3 text-left font-semibold">Email</th>
                    <th className="p-3 text-left font-semibold">Roles</th>
                    <th className="p-3 text-left font-semibold">Source</th>
                    <th className="p-3 text-left font-semibold">Status</th>
                    <th className="p-3 text-left font-semibold">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map(user => (
                    <tr key={user.id} className="border-b hover:bg-gray-50">
                      <td className="p-3">
                        <div>
                          <div className="font-medium">{user.username}</div>
                          {(user.first_name || user.last_name) && (
                            <div className="text-sm text-gray-500">
                              {user.first_name} {user.last_name}
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="p-3 text-sm text-gray-600">{user.email || '-'}</td>
                      <td className="p-3">
                        <div className="flex flex-wrap gap-1">
                          {user.roles && user.roles.length > 0 ? (
                            user.roles.map(role => (
                              <span 
                                key={role.id} 
                                className={`px-2 py-1 text-xs rounded ${
                                  role.is_system 
                                    ? 'bg-purple-100 text-purple-800 border border-purple-200' 
                                    : 'bg-blue-100 text-blue-800'
                                }`}
                              >
                                {role.name}
                              </span>
                            ))
                          ) : (
                            <span className="text-sm text-gray-400 italic">No roles</span>
                          )}
                        </div>
                      </td>
                      <td className="p-3">
                        {(user.is_ad_synced || user.source === 'ad') ? (
                          <span className="px-2 py-1 bg-green-100 text-green-800 text-xs rounded flex items-center gap-1 w-fit">
                            <Shield size={12} /> AD
                          </span>
                        ) : (
                          <span className="px-2 py-1 bg-gray-100 text-gray-800 text-xs rounded flex items-center gap-1 w-fit">
                            <Users size={12} /> Local
                          </span>
                        )}
                      </td>
                      <td className="p-3">
                        {(user.is_active || user.status === 'active') ? (
                          <div className="flex items-center gap-1 text-green-600 text-sm">
                            <CheckCircle size={16} /> Active
                          </div>
                        ) : (
                          <div className="flex items-center gap-1 text-red-600 text-sm">
                            <XCircle size={16} /> Inactive
                          </div>
                        )}
                      </td>
                      <td className="p-3">
                        <div className="flex gap-2">
                          <button
                            onClick={() => { setEditingUser(user); setShowAddUserModal(true); }}
                            className="text-blue-600 hover:text-blue-800 p-1"
                            title="Edit user"
                          >
                            <Edit2 size={18} />
                          </button>
                          <button
                            onClick={() => handleDeleteUser(user.id)}
                            className="text-red-600 hover:text-red-800 p-1"
                            title="Delete user"
                          >
                            <Trash2 size={18} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {showAddUserModal && (
            <UserModal
              user={editingUser}
              availableRoles={roles}
              onSave={handleSaveUser}
              onClose={() => { setShowAddUserModal(false); setEditingUser(null); }}
            />
          )}

          {showAddUserFromADModal && (
            <ADUserModal
              adUsers={adUsers}
              adError={adError}
              availableRoles={roles}
              onSave={handleSaveUserFromAD}
              onClose={() => setShowAddUserFromADModal(false)}
            />
          )}
        </div>
      )}

      {activeTab === 'roles' && (
        <div>
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-2xl font-bold">Roles Management</h2>
            <button
              onClick={() => { setEditingRole(null); setShowAddRoleModal(true); }}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
            >
              <Plus size={20} /> Add Custom Role
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {roles.map(role => (
              <div key={role.id} className="border rounded-lg p-4 bg-white hover:shadow-md transition-shadow">
                <div className="flex justify-between items-start mb-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <h3 className="text-lg font-bold">{role.name}</h3>
                      {role.is_system && (
                        <span className="px-2 py-0.5 bg-purple-100 text-purple-800 text-xs rounded border border-purple-200">
                          System Role
                        </span>
                      )}
                    </div>
                    <p className="text-gray-600 text-sm">{role.description}</p>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => { 
                        if (role.is_system) {
                          setError('System roles cannot be edited');
                          return;
                        }
                        setEditingRole(role); 
                        setShowAddRoleModal(true); 
                      }}
                      className={`p-1 ${
                        role.is_system 
                          ? 'text-gray-400 cursor-not-allowed' 
                          : 'text-blue-600 hover:text-blue-800'
                      }`}
                      title={role.is_system ? 'System roles cannot be edited' : 'Edit role'}
                      disabled={role.is_system}
                    >
                      <Edit2 size={18} />
                    </button>
                    <button
                      onClick={() => handleDeleteRole(role.id, role.is_system || false)}
                      className={`p-1 ${
                        role.is_system 
                          ? 'text-gray-400 cursor-not-allowed' 
                          : 'text-red-600 hover:text-red-800'
                      }`}
                      title={role.is_system ? 'System roles cannot be deleted' : 'Delete role'}
                      disabled={role.is_system}
                    >
                      <Trash2 size={18} />
                    </button>
                  </div>
                </div>
                <div className="border-t pt-3">
                  <p className="text-sm font-semibold text-gray-700 mb-2">
                    Permissions ({role.permissions?.length || 0}):
                  </p>
                  <div className="space-y-1 max-h-40 overflow-y-auto">
                    {role.permissions && role.permissions.length > 0 ? (
                      role.permissions.map(perm => (
                        <div key={perm.id} className="text-sm text-gray-600 flex items-center gap-1">
                          <CheckCircle size={14} className="text-green-600" />
                          {perm.resource} → {perm.action}
                        </div>
                      ))
                    ) : (
                      <p className="text-sm text-gray-400 italic">No permissions assigned</p>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>

          {showAddRoleModal && (
            <RoleModal
              role={editingRole}
              availablePermissions={permissions}
              onSave={handleSaveRole}
              onClose={() => { setShowAddRoleModal(false); setEditingRole(null); }}
            />
          )}
        </div>
      )}

      {activeTab === 'permissions' && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-2xl font-bold">Available Permissions <span className="text-sm text-gray-500">({permissions.length})</span></h2>
            <div className="flex items-center gap-2">
              <input
                type="text"
                placeholder="Search permissions..."
                value={permissionsSearch}
                onChange={(e) => setPermissionsSearch(e.target.value)}
                className="px-3 py-2 border rounded w-64"
              />
              <select className="px-3 py-2 border rounded" value={permissionsCategoryFilter} onChange={(e) => setPermissionsCategoryFilter(e.target.value)}>
                <option value="All">All Categories</option>
                {Array.from(new Set(permissions.map(p => p.category || 'Uncategorized'))).map(cat => (
                  <option key={cat} value={cat}>{cat}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4">
            {permissions.length > 0 ? (
              permissions
                .filter(p => (permissionsCategoryFilter === 'All' || (p.category || 'Uncategorized') === permissionsCategoryFilter))
                .filter(p => p.name.toLowerCase().includes(permissionsSearch.toLowerCase()) || p.description.toLowerCase().includes(permissionsSearch.toLowerCase()) || p.id.toLowerCase().includes(permissionsSearch.toLowerCase()))
                .map(perm => (
                  <div key={perm.id} className="border rounded-lg p-4 bg-white hover:shadow-md transition-shadow">
                    <div className="flex items-start gap-3">
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <div>
                            <div className="font-medium text-lg">{perm.name}</div>
                            <div className="text-xs text-gray-500">{perm.id} • {perm.category}</div>
                          </div>
                          <div className="text-sm text-gray-600">{/* assigned users count */}
                            <span className="inline-block bg-gray-100 px-2 py-1 rounded text-xs">{users.filter(u => (u.roles || []).some(r => (r.permissions || []).some(pr => pr.id === perm.id))).length} user(s)</span>
                          </div>
                        </div>
                        {perm.description && <div className="text-sm text-gray-600 mt-2">{perm.description}</div>}
                      </div>
                      <div className="flex items-start gap-2">
                        <button onClick={() => { setSelectedPermission(perm); setShowPermissionModal(true); }} className="px-3 py-2 bg-blue-600 text-white rounded">View</button>
                      </div>
                    </div>
                  </div>
                ))
            ) : (
              <div className="text-center py-12">
                <p className="text-gray-500">Loading permissions...</p>
              </div>
            )}
          </div>

          {showPermissionModal && selectedPermission && (
            <div className="fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center p-4 z-50">
              <div className="bg-white rounded-lg max-w-lg w-full p-6">
                <div className="flex justify-between items-start">
                  <div>
                    <h3 className="text-xl font-bold">{selectedPermission.name}</h3>
                    <div className="text-xs text-gray-500">{selectedPermission.id} • {selectedPermission.category}</div>
                  </div>
                  <button onClick={() => setShowPermissionModal(false)} className="text-lg">&times;</button>
                </div>
                <div className="mt-4">
                  <p className="text-sm text-gray-700">{selectedPermission.description}</p>
                </div>
                <div className="mt-4">
                  <h4 className="font-semibold mb-2">Assigned Users</h4>
                  <div className="space-y-2">
                    {users.filter(u => (u.roles || []).some(r => (r.permissions || []).some(pr => pr.id === selectedPermission.id))).map(u => (
                      <div key={u.id} className="flex items-center gap-3">
                        <div className="w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center">{(u.first_name || u.username || 'A').charAt(0)}</div>
                        <div>
                          <div className="font-medium">{u.username}</div>
                          <div className="text-sm text-gray-500">{u.email}</div>
                        </div>
                      </div>
                    ))}
                    {users.filter(u => (u.roles || []).every(r => !(r.permissions || []).some(pr => pr.id === selectedPermission.id))).length === users.length && (
                      <p className="text-sm text-gray-500">No users assigned to this permission.</p>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function UserModal({ user, availableRoles, onSave, onClose }: any) {
  const [formError, setFormError] = useState('');
  const [formData, setFormData] = useState({
    username: user?.username || '',
    email: user?.email || '',
    first_name: user?.first_name || '',
    last_name: user?.last_name || '',
    role_ids: user?.roles?.map((r: Role) => r.id) || [],
    password: '',
    confirm_password: '',
    force_password_change: false,
  });

  const validatePassword = (pwd: string) => {
    const errors: string[] = [];
    if (pwd.length < 12) errors.push('at least 12 characters');
    if (!/[A-Z]/.test(pwd)) errors.push('an uppercase letter');
    if (!/[a-z]/.test(pwd)) errors.push('a lowercase letter');
    if (!/[0-9]/.test(pwd)) errors.push('a number');
    if (!/[^A-Za-z0-9]/.test(pwd)) errors.push('a special character');
    return errors;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.username.trim()) {
      setFormError('Username is required');
      return;
    }
    if (formData.role_ids.length === 0) {
      setFormError('Please assign at least one role');
      return;
    }

    // Password validation for new users or when password is provided during edit
    if (!user) {
      if (!formData.password) {
        setFormError('Password is required for new users');
        return;
      }
      const pwErrors = validatePassword(formData.password);
      if (pwErrors.length > 0) {
        setFormError('Password must include: ' + pwErrors.join(', '));
        return;
      }
      if (formData.password !== formData.confirm_password) {
        setFormError('Password and confirmation do not match');
        return;
      }
    } else if (formData.password) {
      // Editing: if password provided, validate
      const pwErrors = validatePassword(formData.password);
      if (pwErrors.length > 0) {
        setFormError('Password must include: ' + pwErrors.join(', '));
        return;
      }
      if (formData.password !== formData.confirm_password) {
        setFormError('Password and confirmation do not match');
        return;
      }
    }

    // Build payload (exclude empty password fields)
    const payload: any = {
      username: formData.username,
      email: formData.email,
      first_name: formData.first_name,
      last_name: formData.last_name,
      role_ids: formData.role_ids,
    };
    if (formData.password) {
      payload.password = formData.password;
      payload.force_password_change = formData.force_password_change;
    }

    onSave(payload);
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg max-w-md w-full p-6">
        <h2 className="text-xl font-bold mb-4">{user ? 'Edit User' : 'Add New Local User'}</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          {formError && (
            <div className="bg-red-50 border border-red-200 text-red-700 text-sm p-3 rounded">
              {formError}
            </div>
          )}
          <div>
            <label className="block text-sm font-semibold mb-1">Username *</label>
            <input
              type="text"
              value={formData.username}
              onChange={(e) => setFormData({ ...formData, username: e.target.value })}
              disabled={!!user}
              className="w-full px-3 py-2 border rounded disabled:bg-gray-100"
              required
              placeholder="e.g., jdoe"
            />
          </div>
          <div>
            <label className="block text-sm font-semibold mb-1">Email</label>
            <input
              type="email"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              className="w-full px-3 py-2 border rounded"
              placeholder="e.g., john.doe@company.com"
            />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="block text-sm font-semibold mb-1">First Name</label>
              <input
                type="text"
                value={formData.first_name}
                onChange={(e) => setFormData({ ...formData, first_name: e.target.value })}
                className="w-full px-3 py-2 border rounded"
                placeholder="John"
              />
            </div>
            <div>
              <label className="block text-sm font-semibold mb-1">Last Name</label>
              <input
                type="text"
                value={formData.last_name}
                onChange={(e) => setFormData({ ...formData, last_name: e.target.value })}
                className="w-full px-3 py-2 border rounded"
                placeholder="Doe"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-semibold mb-1">Assign Roles *</label>
            <div className="space-y-2 max-h-48 overflow-y-auto border rounded p-3">
              {availableRoles.map((role: Role) => (
                <label key={role.id} className="flex items-center cursor-pointer hover:bg-gray-50 p-1 rounded">
                  <input
                    type="checkbox"
                    checked={formData.role_ids.includes(role.id)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setFormData({
                          ...formData,
                          role_ids: [...formData.role_ids, role.id]
                        });
                      } else {
                        setFormData({
                          ...formData,
                          role_ids: formData.role_ids.filter((id: string) => id !== role.id)
                        });
                      }
                    }}
                    className="mr-2"
                  />
                  <span className="text-sm flex-1">{role.name}</span>
                  {role.is_system && (
                    <span className="text-xs bg-purple-100 text-purple-800 px-2 py-0.5 rounded">System</span>
                  )}
                </label>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-sm font-semibold mb-1">Password {user ? '(leave empty to keep current)' : '*'}</label>
            <input
              type="password"
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
              className="w-full px-3 py-2 border rounded"
              placeholder={user ? '•••••••• (leave empty to keep current password)' : 'Strong password'}
            />
          </div>
          <div>
            <label className="block text-sm font-semibold mb-1">Confirm Password</label>
            <input
              type="password"
              value={formData.confirm_password}
              onChange={(e) => setFormData({ ...formData, confirm_password: e.target.value })}
              className="w-full px-3 py-2 border rounded"
              placeholder="Confirm password"
            />
          </div>

          <div className="flex items-center gap-2">
            <input
              id="force-pw"
              type="checkbox"
              checked={formData.force_password_change}
              onChange={(e) => setFormData({ ...formData, force_password_change: e.target.checked })}
              className="mr-2"
            />
            <label htmlFor="force-pw" className="text-sm">Force password change on first login</label>
          </div>

          <div className="flex gap-2 justify-end pt-4 border-t">
            <button type="button" onClick={onClose} className="px-4 py-2 text-gray-600 border rounded hover:bg-gray-50">
              Cancel
            </button>
            <button type="submit" className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">
              {user ? 'Update User' : 'Create User'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function ADUserModal({ adUsers, adError, availableRoles, onSave, onClose }: any) {
  const [selectedADUser, setSelectedADUser] = useState<ADUser | null>(null);
  const [selectedRoles, setSelectedRoles] = useState<string[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [formError, setFormError] = useState('');

  const filteredADUsers = adUsers.filter((user: ADUser) =>
    user.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
    user.full_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    user.email.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedADUser) {
      setFormError('Please select an AD user');
      return;
    }
    if (selectedRoles.length === 0) {
      setFormError('Please assign at least one role');
      return;
    }
    onSave(selectedADUser.distinguished_name, selectedRoles);
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg max-w-2xl w-full p-6 max-h-[90vh] overflow-y-auto">
        <h2 className="text-xl font-bold mb-4">Add User from Active Directory</h2>
        
        {formError && (
          <div className="bg-red-50 border border-red-200 text-red-700 text-sm p-3 rounded mb-4">
            {formError}
          </div>
        )}
        
        {adUsers.length === 0 ? (
          <div className="text-center py-12">
            <Shield size={48} className="mx-auto text-gray-400 mb-4" />
            {adError ? (
              <>
                <p className="text-gray-600 mb-2">Unable to load AD users</p>
                <p className="text-sm text-red-500 mb-2">{adError}</p>
                <p className="text-sm text-gray-500">
                  Active Directory is either not configured or the sync service is unavailable.
                  You can still add local users using the "Add User → Manual User" option.
                </p>
              </>
            ) : (
              <>
                <p className="text-gray-600 mb-2">No AD users available</p>
                <p className="text-sm text-gray-500">
                  Please sync Active Directory users first, or check if the AD sync service is running.
                </p>
              </>
            )}
            <button
              onClick={onClose}
              className="mt-4 px-4 py-2 bg-gray-600 text-white rounded hover:bg-gray-700"
            >
              Close
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-semibold mb-2">Search and Select AD User *</label>
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search by name, username, or email..."
                className="w-full px-3 py-2 border rounded mb-2"
              />
              <div className="border rounded max-h-64 overflow-y-auto">
                {filteredADUsers.length === 0 ? (
                  <p className="p-4 text-gray-500 text-center">No matching AD users found</p>
                ) : (
                  filteredADUsers.map((adUser: ADUser) => (
                    <label
                      key={adUser.distinguished_name}
                      className={`flex items-center p-3 border-b hover:bg-gray-50 cursor-pointer ${
                        adUser.is_already_added ? 'opacity-50' : ''
                      }`}
                    >
                      <input
                        type="radio"
                        name="ad_user"
                        disabled={adUser.is_already_added}
                        checked={selectedADUser?.distinguished_name === adUser.distinguished_name}
                        onChange={() => setSelectedADUser(adUser)}
                        className="mr-3"
                      />
                      <div className="flex-1">
                        <div className="font-medium">{adUser.full_name}</div>
                        <div className="text-sm text-gray-600">{adUser.username} • {adUser.email}</div>
                        {adUser.department && (
                          <div className="text-xs text-gray-500">{adUser.department}</div>
                        )}
                      </div>
                      {adUser.is_already_added && (
                        <span className="text-xs bg-gray-200 text-gray-700 px-2 py-1 rounded">
                          Already Added
                        </span>
                      )}
                    </label>
                  ))
                )}
              </div>
            </div>

            {selectedADUser && !selectedADUser.is_already_added && (
              <div>
                <label className="block text-sm font-semibold mb-2">Assign Roles *</label>
                <div className="space-y-2 border rounded p-3 max-h-48 overflow-y-auto">
                  {availableRoles.map((role: Role) => (
                    <label key={role.id} className="flex items-center cursor-pointer hover:bg-gray-50 p-1 rounded">
                      <input
                        type="checkbox"
                        checked={selectedRoles.includes(role.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedRoles([...selectedRoles, role.id]);
                          } else {
                            setSelectedRoles(selectedRoles.filter(id => id !== role.id));
                          }
                        }}
                        className="mr-2"
                      />
                      <span className="text-sm flex-1">{role.name}</span>
                      {role.is_system && (
                        <span className="text-xs bg-purple-100 text-purple-800 px-2 py-0.5 rounded">System</span>
                      )}
                    </label>
                  ))}
                </div>
              </div>
            )}

            <div className="flex gap-2 justify-end pt-4 border-t">
              <button type="button" onClick={onClose} className="px-4 py-2 text-gray-600 border rounded hover:bg-gray-50">
                Cancel
              </button>
              <button 
                type="submit" 
                disabled={!selectedADUser || selectedADUser.is_already_added || selectedRoles.length === 0}
                className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Add User from AD
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

function RoleModal({ role, availablePermissions, onSave, onClose }: any) {
  const [formError, setFormError] = useState('');
  const [formData, setFormData] = useState({
    name: role?.name || '',
    description: role?.description || '',
    permission_ids: role?.permissions?.map((p: Permission) => p.id) || [],
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name.trim()) {
      setFormError('Role name is required');
      return;
    }
    onSave(formData);
  };

  const permsByResource = availablePermissions.reduce((acc: any, perm: Permission) => {
    if (!acc[perm.resource]) acc[perm.resource] = [];
    acc[perm.resource].push(perm);
    return acc;
  }, {});

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg max-w-3xl w-full p-6 max-h-[90vh] overflow-y-auto">
        <h2 className="text-xl font-bold mb-4">
          {role ? (role.is_system ? 'View System Role' : 'Edit Custom Role') : 'Add New Custom Role'}
        </h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          {formError && (
            <div className="bg-red-50 border border-red-200 text-red-700 text-sm p-3 rounded">
              {formError}
            </div>
          )}
          <div>
            <label className="block text-sm font-semibold mb-1">Role Name *</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 border rounded"
              required
              placeholder="e.g., Custom Auditor"
              disabled={role?.is_system}
            />
          </div>
          <div>
            <label className="block text-sm font-semibold mb-1">Description</label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full px-3 py-2 border rounded"
              rows={2}
              placeholder="Brief description of this role's purpose"
              disabled={role?.is_system}
            />
          </div>
          <div>
            <label className="block text-sm font-semibold mb-3">Assign Permissions</label>
            <div className="grid grid-cols-2 gap-4 max-h-96 overflow-y-auto">
              {Object.entries(permsByResource).map(([resource, perms]: any) => (
                <div key={resource} className="border rounded p-3 bg-gray-50">
                  <h4 className="font-semibold text-sm mb-2 text-gray-700">{resource}</h4>
                  <div className="space-y-2">
                    {perms.map((perm: Permission) => (
                      <label key={perm.id} className="flex items-center text-sm cursor-pointer hover:bg-white p-1 rounded">
                        <input
                          type="checkbox"
                          checked={formData.permission_ids.includes(perm.id)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setFormData({
                                ...formData,
                                permission_ids: [...formData.permission_ids, perm.id]
                              });
                            } else {
                              setFormData({
                                ...formData,
                                permission_ids: formData.permission_ids.filter((id: string) => id !== perm.id)
                              });
                            }
                          }}
                          className="mr-2"
                          disabled={role?.is_system}
                        />
                        <span className="flex-1">{perm.action}</span>
                        {perm.is_implemented === false && (
                          <span className="text-xs bg-yellow-100 text-yellow-800 px-1 py-0.5 rounded ml-1">Soon</span>
                        )}
                      </label>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="flex gap-2 justify-end pt-4 border-t">
            <button type="button" onClick={onClose} className="px-4 py-2 text-gray-600 border rounded hover:bg-gray-50">
              {role?.is_system ? 'Close' : 'Cancel'}
            </button>
            {!role?.is_system && (
              <button type="submit" className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">
                {role ? 'Update Role' : 'Create Role'}
              </button>
            )}
          </div>
        </form>
      </div>
    </div>
  );
}
