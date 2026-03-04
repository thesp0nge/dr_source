package com.example.legacy;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.persistence.EntityManager;
import javax.persistence.Query;
import java.io.IOException;

public class LegacyAndHibernate extends HttpServlet {

    private EntityManager em;

    // 1. Jakarta EE Servlet Test
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("name");
        
        // VULNERABLE: XSS via Servlet response writer
        response.getWriter().write("Hello " + userInput);
        
        // VULNERABLE: SQL Injection via Hibernate
        runHibernateQuery(userInput);
    }

    // 2. Hibernate Test
    public void runHibernateQuery(String tainted) {
        // VULNERABLE: createQuery with string concatenation
        String hql = "FROM User WHERE name = '" + tainted + "'";
        Query query = em.createQuery(hql);
        query.getResultList();
        
        // SAFE: constant query (should be ignored)
        em.createQuery("FROM User WHERE id = 1").getResultList();
    }
}
