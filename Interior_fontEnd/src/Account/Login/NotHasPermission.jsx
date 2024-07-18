import { useNavigate } from "react-router-dom";

function NotHasPermission() {
    const navi = useNavigate()
    return ( 
        <div className="container mt-3">
            <h2>Bạn không có quyền truy cập vào Đường Dẫn này</h2>
            <span>Nhằm Role rồi</span>
            <button className="btn btn-danger d-block" onClick={() => navi(-2)}>Trở lại trang trước</button>
        </div>
     );
}

export default NotHasPermission;