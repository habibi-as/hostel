import React from 'react';
import StudentLayout from '../../components/student/StudentLayout';

const StudentFees = () => {
  return (
    <StudentLayout>
      <div className="space-y-6">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          Fees
        </h1>
        
        <div className="card">
          <div className="card-content">
            <p className="text-gray-600 dark:text-gray-400">
              Fee management functionality will be implemented here.
            </p>
          </div>
        </div>
      </div>
    </StudentLayout>
  );
};

export default StudentFees;
