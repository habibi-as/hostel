import React from 'react';

const StatsCard = ({ title, value, icon, color, description }) => {
  const colorClasses = {
    primary: 'from-primary-500 to-primary-600',
    gold: 'from-gold-500 to-gold-600',
    green: 'from-green-500 to-green-600',
    red: 'from-red-500 to-red-600',
    blue: 'from-blue-500 to-blue-600',
    purple: 'from-purple-500 to-purple-600'
  };

  const bgClass = colorClasses[color] || colorClasses.primary;

  return (
    <div className={`bg-gradient-to-r ${bgClass} rounded-lg p-6 text-white shadow-lg hover:shadow-xl transition-shadow duration-300`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-white opacity-90 text-sm font-medium">
            {title}
          </p>
          <p className="text-3xl font-bold mt-2">
            {value}
          </p>
          <p className="text-white opacity-75 text-xs mt-1">
            {description}
          </p>
        </div>
        <div className="opacity-80">
          {icon}
        </div>
      </div>
    </div>
  );
};

export default StatsCard;
