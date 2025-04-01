export const Card = ({ className = '', children }) => (
    <div className={`bg-white rounded-lg shadow-lg ${className}`}>{children}</div>
  );
  
  export const CardHeader = ({ className = '', children }) => (
    <div className={`p-6 border-b ${className}`}>{children}</div>
  );
  
  export const CardTitle = ({ className = '', children }) => (
    <h2 className={`text-2xl font-semibold ${className}`}>{children}</h2>
  );
  
  export const CardContent = ({ className = '', children }) => (
    <div className={`p-6 ${className}`}>{children}</div>
  );