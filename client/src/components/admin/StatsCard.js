import React from 'react';
import { FaArrowUp, FaArrowDown } from 'react-icons/fa';

const StatsCard = ({ title, value, icon, color, change, changeType }) => {
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
          {change && (
            <div className="flex items-center mt-2">
              {changeType === 'positive' ? (
                <FaArrowUp className="w-3 h-3 text-green-200 mr-1" />
              ) : (
                <FaArrowDown className="w-3 h-3 text-red-200 mr-1" />
              )}
              <span className={`text-sm ${
                changeType === 'positive' ? 'text-green-200' : 'text-red-200'
              }`}>
                {change}
              </span>
            </div>
          )}
        </div>
        <div className="opacity-80">
          {icon}
        </div>
      </div>
    </div>
  );
};

export default StatsCard;
