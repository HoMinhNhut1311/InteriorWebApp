import { useNavigate } from 'react-router-dom';
import { useEffect } from 'react';
function ProtectedRoute({ children }) {
    const token = sessionStorage.token;
    const navigate = useNavigate();
    const isAuthen = token != null;
    useEffect(() => {
        if (!isAuthen) {
            navigate('/login');
        }
    }, [isAuthen, navigate]);

    return children;
}

export default ProtectedRoute;
