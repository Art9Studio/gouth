package router

import (
	"github.com/gofiber/fiber/v2"
	"path"
)

type TRouter struct {
	Routes map[string][]*Route
}

type Route struct {
	Method  string
	Path    string
	Handler func(*fiber.Ctx) error
}

var Router TRouter

type App interface {
	GetPathPrefix() string
}

// CreateServer initializes router and creates routes for each application
func CreateServer(apps map[string]interface{}) (*fiber.App, error) {
	r := fiber.New()
	v := r.Group("")

	for appName, routes := range Router.Routes {
		pathPrefix := apps.(map[string]*App).GetPathPrefix()
		appR := v.Group(pathPrefix)

		for _, route := range routes {
			appR.Add(route.Method, route.Path, route.Handler)
		}
	}

	return r, nil
}

func Init() TRouter {
	Router = TRouter{
		Routes: make(map[string][]*Route),
	}
	return Router
}

func (r TRouter) Add(appName string, routes []*Route) {
	for i := range routes {
		routes[i].Path = path.Clean(routes[i].Path)
	}

	if existRoutes, ok := r.Routes[appName]; ok {
		r.Routes[appName] = append(existRoutes, routes...)
	} else {
		r.Routes[appName] = routes
	}
}
