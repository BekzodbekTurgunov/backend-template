export function routeErrorHandler(route: string, error: any, res: any) {
    const message = error.message || "An unexpected error occurred";
    console.error(`Error in ${route}: ${message}`)
    res.status(500).json({
        message: `International server error on ${route}`,
    });
}
