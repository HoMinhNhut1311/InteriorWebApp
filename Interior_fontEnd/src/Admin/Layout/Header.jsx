import { faExpand, faWindowMaximize } from '@fortawesome/free-solid-svg-icons';
import catImage from '/public/images/sofa.png'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { useNavigate } from 'react-router-dom';



function Header({handleLogOut, toggleLite, isLite}) {

  const navigate = useNavigate();

    const hanldeGoBack = () => {
      navigate(-1)
    }

    return ( 
             <header className="header p-0">
        <nav className="navbar navbar-expand-lg py-3 bg-dash-dark-2 border-bottom border-dash-dark-1 z-index-10">
          <div className="container-fluid d-flex align-items-center justify-content-between py-1">
            <div className="navbar-header d-flex align-items-center">
              <span
                className="navbar-brand text-uppercase text-reset"
              >
                <div className="brand-text brand-big">
                  <strong className="text-warning">SHOPP</strong>
                  <strong className='text-white'>ER</strong>
                </div>
                <div className="brand-text brand-sm">
                  <strong className="text-primary">NH</strong>
                  <strong>A</strong>
                </div>
              </span>
              <button className="sidebar-toggle sidebar-header d-flex align-items-center p-4">
                <img src={catImage} alt="" className='avatar shadow-0 rounded-circle' />
              </button>
            </div>
            <ul className="list-inline mb-0"> 
              <button className='m-2 btn btn-outline-success' onClick={() => toggleLite()}>
      {isLite ?<FontAwesomeIcon icon={faExpand}/> : <FontAwesomeIcon icon={faWindowMaximize} />}
              </button>
              <button className='btn btn-primary' onClick={() => hanldeGoBack()}>Trở lại trang trước</button>


              <li className="list-inline-item logout px-lg-2">
                <button className='btn btn-outline-warning' onClick={(e) => handleLogOut(e)}>Đăng xuất</button>
              </li>
            </ul>
          </div>
        </nav>
      </header>
    );
}

export default Header;