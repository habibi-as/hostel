import React from 'react';
import AdminLayout from '../../components/admin/AdminLayout';

const AdminReports = () => {
  return (
    <AdminLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Reports & Analytics
          </h1>
        </div>
        
        <div className="card">
          <div className="card-content">
            <p className="text-gray-600 dark:text-gray-400">
              Reports and analytics functionality will be implemented here.
            </p>
          </div>
        </div>
      </div>
    </AdminLayout>
  );
};

export default AdminReports;
