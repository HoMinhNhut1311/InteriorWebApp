import { useNavigate } from "react-router-dom"


const PageNotFound = () => {
    const navigate = useNavigate()

    return (
        <div className="bg-white">
            <h2>Page Not Found : 404</h2>
            <h3>Đường dẫn không tồn tại</h3>
            <button onClick={() => navigate('-1')} className="btn btn-warning">Trở lại trang chủ</button>
        </div>
    )
}

export default PageNotFound