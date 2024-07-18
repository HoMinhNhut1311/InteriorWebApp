import {  faGraduationCap, faIgloo, faUsersGear, faUsersViewfinder } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import catImage from '/public/images/sofa.png'
import { Link } from "react-router-dom";

function Sidebar({handleActive, active , isLite}) {

    return ( 
        <nav id={isLite ?"sidebar sidebar-lite": "sidebar" }>
        {/* Sidebar Header*/}
        <div className="sidebar-header d-flex align-items-center p-4">
          <img
            className="avatar shadow-0 img-fluid rounded-circle"
            src={catImage}
            alt="..."
          />
          <div className="ms-3 title">
            <h1 className="h5 mb-1">WMN</h1>
            <p className="text-sm text-gray-700 mb-0 lh-1">SHOPPER</p>
          </div>
        </div>
        <span className="text-uppercase text-gray-600 text-xs mx-3 px-2 heading mb-2">
          Dash Board
        </span>
        <ul className="list-unstyled">
          <li className={active.numberPage === 1 ? 'sidebar-item active' : 'sidebar-item'} onClick={() => handleActive({
            numberPage : 1,
            title : '',
            des : 'Đây là Trang Chủ'
          })}>
            <Link className="sidebar-link" to="">
              <svg className="svg-icon svg-icon-sm svg-icon-heavy">
              <FontAwesomeIcon icon={faIgloo} />
              </svg>
              <span className='nav-text '>Trang Chủ</span>
            </Link>
          </li>
          <li className={active.numberPage === 2 ? 'sidebar-item active' : 'sidebar-item'} onClick={() => handleActive({
             numberPage : 2,
             title : 'Danh Sách Người Dùng',
             des : 'Danh sách thông tin người dùng'
          })}>
            <Link className="sidebar-link" to="user/overview">
              <svg className="svg-icon svg-icon-sm svg-icon-heavy">
              <FontAwesomeIcon icon={faUsersViewfinder} />
              </svg>
              <span className='nav-text '>Danh Sách Người Dùng</span>
            </Link>
          </li>
          <li className={active.numberPage === 3 ? 'sidebar-item active' : 'sidebar-item'} onClick={() => handleActive({
            numberPage : 3,
            title : 'Tìm kiếm người dùng',
            des : 'Tìm kiếm người dùng bằng username'
          })}>
            <Link className="sidebar-link" to="user/search">
              <svg className="svg-icon svg-icon-sm svg-icon-heavy">
              <FontAwesomeIcon icon={faUsersGear} />
              </svg>
              <span className='nav-text '>Tìm kiếm người dùng</span>
            </Link>
          </li>
          <li  className={active.numberPage === 4 ? 'sidebar-item active' : 'sidebar-item'} onClick={() => handleActive({
            numberPage : 4,
            title : 'Danh sách sản phẩm',
            des : ''
          })}>
            <Link className="sidebar-link" to={"product/overview"}>
              <svg className="svg-icon svg-icon-sm svg-icon-heavy">
              <FontAwesomeIcon icon={faGraduationCap} />
              </svg>
              <span>Quản lí sản phẩm</span>
            </Link>
          </li>

          <li  className={active.numberPage === 5 ? 'sidebar-item active' : 'sidebar-item'} onClick={() => handleActive({
            numberPage : 5,
            title : 'Thống kê doanh thu',
            des : ''
          })}>
            <Link className="sidebar-link" to={"revenue/overview"}>
              <svg className="svg-icon svg-icon-sm svg-icon-heavy">
              <FontAwesomeIcon icon={faGraduationCap} />
              </svg>
              <span>Thống kê doanh thu</span>
            </Link>
          </li>
        </ul>
        
      </nav>

     );
}

export default Sidebar;