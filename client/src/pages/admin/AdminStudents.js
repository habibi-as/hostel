import React from 'react';
import AdminLayout from '../../components/admin/AdminLayout';

const AdminStudents = () => {
  return (
    <AdminLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Student Management
          </h1>
          <button className="btn btn-primary">
            Add Student
          </button>
        </div>
        
        <div className="card">
          <div className="card-content">
            <p className="text-gray-600 dark:text-gray-400">
              Student management functionality will be implemented here.
            </p>
          </div>
        </div>
      </div>
    </AdminLayout>
  );
};

export default AdminStudents;
