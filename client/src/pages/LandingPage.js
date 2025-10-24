import React from 'react';
import { Link } from 'react-router-dom';
import { useTheme } from '../contexts/ThemeContext';
import { 
  FaWifi, 
  FaUtensils, 
  FaShieldAlt, 
  FaDumbbell, 
  FaCar, 
  FaBook,
  FaStar,
  FaArrowRight,
  FaSun,
  FaMoon
} from 'react-icons/fa';

const LandingPage = () => {
  const { darkMode, toggleDarkMode } = useTheme();

  const facilities = [
    {
      icon: <FaWifi className="w-8 h-8 text-primary-600" />,
      title: "High-Speed WiFi",
      description: "Free high-speed internet access throughout the hostel"
    },
    {
      icon: <FaUtensils className="w-8 h-8 text-primary-600" />,
      title: "Quality Meals",
      description: "Nutritious and delicious meals served three times daily"
    },
    {
      icon: <FaShieldAlt className="w-8 h-8 text-primary-600" />,
      title: "24/7 Security",
      description: "Round-the-clock security with CCTV surveillance"
    },
    {
      icon: <FaDumbbell className="w-8 h-8 text-primary-600" />,
      title: "Fitness Center",
      description: "Well-equipped gym for your fitness needs"
    },
    {
      icon: <FaCar className="w-8 h-8 text-primary-600" />,
      title: "Parking",
      description: "Secure parking space for vehicles"
    },
    {
      icon: <FaBook className="w-8 h-8 text-primary-600" />,
      title: "Study Rooms",
      description: "Quiet study areas and library access"
    }
  ];

  const testimonials = [
    {
      name: "Rajesh Kumar",
      batch: "2023 Batch",
      rating: 5,
      comment: "Excellent facilities and great management. The hostel provides everything a student needs."
    },
    {
      name: "Priya Sharma",
      batch: "2022 Batch",
      rating: 5,
      comment: "Clean rooms, good food, and helpful staff. Highly recommended for students."
    },
    {
      name: "Amit Singh",
      batch: "2023 Batch",
      rating: 5,
      comment: "The hostel management system is very efficient. Everything is digital and easy to use."
    }
  ];

  return (
    <div className={`min-h-screen ${darkMode ? 'dark bg-gray-900' : 'bg-gray-50'}`}>
      {/* Header */}
      <header className={`${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-sm`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <h1 className="text-2xl font-bold gradient-text">HostelHub</h1>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <button
                onClick={toggleDarkMode}
                className="p-2 rounded-lg bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
              >
                {darkMode ? <FaSun className="w-5 h-5" /> : <FaMoon className="w-5 h-5" />}
              </button>
              <Link
                to="/login"
                className="btn btn-outline"
              >
                Login
              </Link>
              <Link
                to="/register"
                className="btn btn-primary"
              >
                Register
              </Link>
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-20 bg-gradient-to-br from-primary-50 to-gold-50 dark:from-gray-800 dark:to-gray-900">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <h1 className="text-4xl md:text-6xl font-bold text-gray-900 dark:text-white mb-6">
              Welcome to{' '}
              <span className="gradient-text">HostelHub</span>
            </h1>
            <p className="text-xl text-gray-600 dark:text-gray-300 mb-8 max-w-3xl mx-auto">
              Your premium 5-star hostel management experience. Modern facilities, 
              digital management, and exceptional service for students.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link
                to="/register"
                className="btn btn-primary btn-lg inline-flex items-center"
              >
                Get Started
                <FaArrowRight className="ml-2" />
              </Link>
              <Link
                to="/login"
                className="btn btn-outline btn-lg"
              >
                Student Login
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 bg-white dark:bg-gray-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white mb-4">
              Premium Facilities
            </h2>
            <p className="text-lg text-gray-600 dark:text-gray-300">
              Experience world-class amenities designed for your comfort and success
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {facilities.map((facility, index) => (
              <div
                key={index}
                className="card hover:shadow-lg transition-shadow duration-300"
              >
                <div className="card-content text-center">
                  <div className="flex justify-center mb-4">
                    {facility.icon}
                  </div>
                  <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                    {facility.title}
                  </h3>
                  <p className="text-gray-600 dark:text-gray-300">
                    {facility.description}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Testimonials Section */}
      <section className="py-20 bg-gray-50 dark:bg-gray-900">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white mb-4">
              What Students Say
            </h2>
            <p className="text-lg text-gray-600 dark:text-gray-300">
              Hear from our satisfied residents
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {testimonials.map((testimonial, index) => (
              <div
                key={index}
                className="card hover:shadow-lg transition-shadow duration-300"
              >
                <div className="card-content">
                  <div className="flex items-center mb-4">
                    {[...Array(testimonial.rating)].map((_, i) => (
                      <FaStar key={i} className="w-5 h-5 text-yellow-400" />
                    ))}
                  </div>
                  <p className="text-gray-600 dark:text-gray-300 mb-4">
                    "{testimonial.comment}"
                  </p>
                  <div>
                    <p className="font-semibold text-gray-900 dark:text-white">
                      {testimonial.name}
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      {testimonial.batch}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 bg-gradient-to-r from-primary-600 to-gold-600">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
            Ready to Experience Premium Hostel Life?
          </h2>
          <p className="text-xl text-white opacity-90 mb-8">
            Join thousands of satisfied students who call HostelHub home
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link
              to="/register"
              className="btn bg-white text-primary-600 hover:bg-gray-100 btn-lg inline-flex items-center"
            >
              Register Now
              <FaArrowRight className="ml-2" />
            </Link>
            <Link
              to="/login"
              className="btn border-2 border-white text-white hover:bg-white hover:text-primary-600 btn-lg"
            >
              Student Login
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className={`${darkMode ? 'bg-gray-800' : 'bg-gray-900'} text-white`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            <div>
              <h3 className="text-xl font-bold mb-4">HostelHub</h3>
              <p className="text-gray-400">
                Premium hostel management system for modern students.
              </p>
            </div>
            <div>
              <h4 className="text-lg font-semibold mb-4">Quick Links</h4>
              <ul className="space-y-2">
                <li><Link to="/login" className="text-gray-400 hover:text-white">Login</Link></li>
                <li><Link to="/register" className="text-gray-400 hover:text-white">Register</Link></li>
                <li><Link to="/forgot-password" className="text-gray-400 hover:text-white">Forgot Password</Link></li>
              </ul>
            </div>
            <div>
              <h4 className="text-lg font-semibold mb-4">Support</h4>
              <ul className="space-y-2">
                <li><span className="text-gray-400">Email: support@hostelhub.com</span></li>
                <li><span className="text-gray-400">Phone: +91-XXXX-XXXX</span></li>
                <li><span className="text-gray-400">24/7 Support Available</span></li>
              </ul>
            </div>
            <div>
              <h4 className="text-lg font-semibold mb-4">Follow Us</h4>
              <div className="flex space-x-4">
                <a href="#" className="text-gray-400 hover:text-white">
                  <span className="sr-only">Facebook</span>
                  <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/>
                  </svg>
                </a>
                <a href="#" className="text-gray-400 hover:text-white">
                  <span className="sr-only">Twitter</span>
                  <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z"/>
                  </svg>
                </a>
              </div>
            </div>
          </div>
          <div className="border-t border-gray-700 mt-8 pt-8 text-center">
            <p className="text-gray-400">
              © 2024 HostelHub. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default LandingPage;
