import React from 'react';
import AdminLayout from '../../components/admin/AdminLayout';

const AdminAttendance = () => {
  return (
    <AdminLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Attendance Management
          </h1>
        </div>
        
        <div className="card">
          <div className="card-content">
            <p className="text-gray-600 dark:text-gray-400">
              Attendance management functionality will be implemented here.
            </p>
          </div>
        </div>
      </div>
    </AdminLayout>
  );
};

export default AdminAttendance;
