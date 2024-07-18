import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { publicRoutes, privateRoutes } from './routes';
import ProtectedRoute from './Account/Login/ProtectedRoute';
import PageNotFound from './routes/NotFound/PageNotFound';


function App() {
  return (
    <Router>
      <div className='App'>
        <Routes>
            {createRoutesPublic(publicRoutes)}
            {createRoutesPrivate(privateRoutes)}
            <Route path='*' element={<PageNotFound/>}></Route>
        </Routes>
      </div>
    </Router>
  );
}

const createRoutesPublic = (routes) => {
  return routes.map((route, index) => {
    if (route.childrenRoute) {
      return (
        <Route key={index} path={route.path} element={route.component ? 
            <route.component />
        : null}>
          {createRoutesPublic(route.childrenRoute)}
        </Route>
      );
    } else {
      return (
        <Route key={index} path={route.path} element={route.component ? 
          <route.component />
          : null} />
      );
    }
  });
};

const createRoutesPrivate = (routes) => {
  return routes.map((route, index) => {
    if (route.childrenRoute) {
      return (
        <Route key={index} path={route.path} element={route.component ? 
          <ProtectedRoute>
            <route.component />
           </ProtectedRoute>
        : null}>
          {createRoutesPrivate(route.childrenRoute)}
        </Route>
      );
    } else {
      return (
        <Route key={index} path={route.path} element={route.component ? 
          <ProtectedRoute>
          <route.component />
         </ProtectedRoute>
          : null} />
      );
    }
  });
};

export default App;
